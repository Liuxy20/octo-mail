// Package projections holds async, rebuildable folds of the change-log that do
// not need read-your-write consistency — full-text search first. A projection
// worker folds the messages table by createseq (which equals the changelog seq
// at insertion) behind a per-account high-water cursor, so delivery latency is
// never coupled to indexing. Adding a projection means inserting a cursor at
// 0 and letting the worker fold the whole history up to the live head, then stay
// live — no lock, no downtime. Dropping and rebuilding is the same code path
// from seq 0.
package projection

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	moxmessage "github.com/mjl-/mox/message"
)

// FTSWorker folds message bodies into the fts tsvector projection.
type FTSWorker struct {
	Pool *pgxpool.Pool
	Blob blob.Store
	// Batch bounds how many messages are indexed per RunOnce call per account.
	Batch int
	// MaxMessageSize bounds the raw MIME source parsed for one message. The
	// composition root passes OCTO_MAIL_MAX_SIZE so the projection follows the
	// same deployment contract as SMTP/JMAP/WebAPI.
	MaxMessageSize int64
}

const ftsCursor = "fts"

// Keep projection rows bounded. Ordinary mail is indexed in full; very large
// MIME messages are truncated so attachments cannot exceed PostgreSQL's
// tsvector input limit or make substring scans unbounded.
const maxSearchTextBytes = 512 * 1024

const defaultMaxSearchSourceBytes = 50 << 20

type ftsMessage struct {
	id      int64
	seq     int64
	blobRef string
	prefix  []byte
}

// RunOnceAccount indexes one bounded batch of new messages and one bounded
// batch of legacy rows for one account. New mail remains first, while the
// independent legacy batch guarantees search_text backfill still progresses on
// continuously busy accounts. Returns the total number of messages indexed.
func (w *FTSWorker) RunOnceAccount(ctx context.Context, tenantID, accountID int64) (int, error) {
	batch := w.Batch
	if batch <= 0 {
		batch = 100
	}

	// Read the cursor (0 if absent).
	var cursor int64
	err := w.Pool.QueryRow(ctx,
		`SELECT seq FROM projection_cursor WHERE account_id=$1 AND name=$2`,
		accountID, ftsCursor).Scan(&cursor)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		cursor = 0
	}

	// Always index new mail first through the createseq range index. Keeping the
	// forward and legacy queries separate avoids the old OR predicate that forced
	// a full messages scan on every steady-state tick.
	msgs, err := loadFTSBatch(ctx, w.Pool,
		`SELECT m.id, m.createseq, m.blob_ref, m.msg_prefix
		 FROM messages m
		 WHERE m.account_id=$1 AND m.createseq>$2
		 ORDER BY m.createseq
		 LIMIT $3`, accountID, cursor, batch)
	if err != nil {
		return 0, err
	}
	indexed := 0
	if len(msgs) > 0 {
		if err := w.indexFTSBatch(ctx, tenantID, accountID, cursor, msgs); err != nil {
			return 0, err
		}
		indexed += len(msgs)
		cursor = msgs[len(msgs)-1].seq
	}

	// Run a separate bounded legacy sweep on every tick. A busy account may
	// never have an empty forward batch, so coupling this query to forward-idle
	// would permanently starve historical rows.
	legacy, err := loadFTSBatch(ctx, w.Pool,
		`SELECT m.id, m.createseq, m.blob_ref, m.msg_prefix
		 FROM fts f
		 JOIN messages m ON m.account_id=f.account_id AND m.id=f.message_id
		 WHERE f.account_id=$1 AND f.search_text IS NULL
		 ORDER BY f.message_id
		 LIMIT $2`, accountID, batch)
	if err != nil {
		return indexed, err
	}
	if len(legacy) > 0 {
		if err := w.indexFTSBatch(ctx, tenantID, accountID, cursor, legacy); err != nil {
			return indexed, err
		}
		indexed += len(legacy)
	}
	return indexed, nil
}

func (w *FTSWorker) indexFTSBatch(ctx context.Context, tenantID, accountID int64, cursor int64, msgs []ftsMessage) error {
	// Phase 1 — read each message's text OUTSIDE any transaction (blob reads are
	// network I/O; holding a tx open across the whole batch would be a long-lived
	// transaction).
	texts := make([]string, len(msgs))
	for i, m := range msgs {
		text, err := w.readText(ctx, tenantID, m.blobRef, m.prefix)
		if err != nil {
			return err
		}
		texts[i] = text
	}

	// Phase 2 — upsert every tsvector and advance the cursor in ONE transaction, so
	// the cursor moves iff all upserts in the batch are durable. A crash mid-batch
	// rolls back and the batch re-runs from the unchanged cursor.
	maxSeq := cursor
	err := pgx.BeginFunc(ctx, w.Pool, func(tx pgx.Tx) error {
		for i, m := range msgs {
			// Upsert the tsvector. to_tsvector runs in Postgres so we never ship a
			// parsed vector over the wire.
			if _, err := tx.Exec(ctx,
				`INSERT INTO fts (account_id, message_id, tsv, search_text)
				 VALUES ($1,$2, to_tsvector('simple', $3), $3)
				 ON CONFLICT (account_id, message_id)
				 DO UPDATE SET tsv = EXCLUDED.tsv, search_text = EXCLUDED.search_text`,
				accountID, m.id, texts[i]); err != nil {
				return err
			}
			if m.seq > maxSeq {
				maxSeq = m.seq
			}
		}
		// Advance the cursor to the highest indexed seq.
		if _, err := tx.Exec(ctx,
			`INSERT INTO projection_cursor (account_id, name, seq)
			 VALUES ($1,$2,$3)
			 ON CONFLICT (account_id, name)
			 DO UPDATE SET seq=EXCLUDED.seq`,
			accountID, ftsCursor, maxSeq); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// DrainAccount runs RunOnceAccount until the projection is caught up.
func (w *FTSWorker) DrainAccount(ctx context.Context, tenantID, accountID int64) error {
	for {
		n, err := w.RunOnceAccount(ctx, tenantID, accountID)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

// RebuildAccount drops the fts projection for an account and resets its cursor,
// so the next Drain/RunOnce re-folds the whole log from seq 0. This is the
// "rebuild a projection" primitive — the same fold, from the beginning.
func (w *FTSWorker) RebuildAccount(ctx context.Context, tenantID, accountID int64) error {
	if _, err := w.Pool.Exec(ctx, `DELETE FROM fts WHERE account_id=$1`, accountID); err != nil {
		return err
	}
	if _, err := w.Pool.Exec(ctx,
		`INSERT INTO projection_cursor (account_id, name, seq) VALUES ($1,$2,0)
		 ON CONFLICT (account_id, name) DO UPDATE SET seq=0`,
		accountID, ftsCursor); err != nil {
		return err
	}
	return w.DrainAccount(ctx, tenantID, accountID)
}

// readText returns the indexable text of a message: the generated prefix
// (headers) followed by the stored body. Postgres tokenizes it via to_tsvector.
func (w *FTSWorker) readText(ctx context.Context, tenantID int64, blobRef string, prefix []byte) (string, error) {
	r, err := w.Blob.Open(ctx, tenantID, blob.Ref(blobRef))
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) || errors.Is(err, blob.ErrBadRef) {
			return boundedSearchText(prefix, nil), nil
		}
		return "", err
	}
	defer r.Close()
	maxSource := w.MaxMessageSize
	if maxSource <= 0 {
		maxSource = defaultMaxSearchSourceBytes
	}
	body, err := io.ReadAll(io.LimitReader(r, maxSource+1))
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) || errors.Is(err, blob.ErrBadRef) {
			return boundedSearchText(prefix, nil), nil
		}
		return "", err
	}
	if int64(len(body)) > maxSource {
		body = body[:maxSource]
	}
	full := make([]byte, 0, len(prefix)+len(body))
	full = append(full, prefix...)
	full = append(full, body...)
	return extractSearchText(full), nil
}

func boundedSearchText(prefix, body []byte) string {
	data := make([]byte, 0, min(len(prefix)+len(body), maxSearchTextBytes))
	data = append(data, prefix...)
	data = append(data, body...)
	if len(data) > maxSearchTextBytes {
		data = data[:maxSearchTextBytes]
	}
	// PostgreSQL text rejects NUL even though it is valid UTF-8. The shared
	// projection sanitizer also removes malformed UTF-8 so one legacy message
	// cannot wedge the account cursor forever.
	return toValidUTF8(string(bytes.ToValidUTF8(data, []byte(" "))))
}

func loadFTSBatch(ctx context.Context, pool *pgxpool.Pool, query string, args ...any) ([]ftsMessage, error) {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var msgs []ftsMessage
	for rows.Next() {
		var m ftsMessage
		if err := rows.Scan(&m.id, &m.seq, &m.blobRef, &m.prefix); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// extractSearchText preserves searchable RFC message headers and attachment
// names while also indexing charset- and transfer-decoded user-visible text.
func extractSearchText(raw []byte) string {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.Envelope == nil && len(part.Parts) == 0 {
		return boundedSearchText(nil, raw)
	}

	data := make([]byte, 0, min(len(raw), maxSearchTextBytes))
	appendText := func(value string) {
		if len(data) >= maxSearchTextBytes {
			return
		}
		value = toValidUTF8(value)
		remaining := maxSearchTextBytes - len(data)
		if len(value) > remaining {
			value = value[:remaining]
			for len(value) > 0 && !utf8.ValidString(value) {
				value = value[:len(value)-1]
			}
		}
		data = append(data, value...)
		if len(data) < maxSearchTextBytes {
			data = append(data, '\n')
		}
	}
	if env := part.Envelope; env != nil {
		appendText(env.Subject)
		appendText(addrSearch(env.From))
		appendText(addrSearch(env.To))
		appendText(addrSearch(env.CC))
		appendText(addrSearch(env.BCC))
	}

	var walk func(*moxmessage.Part)
	walk = func(current *moxmessage.Part) {
		if len(data) >= maxSearchTextBytes {
			return
		}
		// IMAP SEARCH TEXT includes headers as well as bodies. Preserve every
		// top-level and MIME-part header instead of narrowing search to Envelope.
		header, _ := io.ReadAll(io.LimitReader(current.HeaderReader(), int64(maxSearchTextBytes-len(data))+1))
		appendText(string(header))
		_, filename, _ := current.DispositionFilename()
		appendText(filename)
		if len(current.Parts) > 0 {
			for i := range current.Parts {
				walk(&current.Parts[i])
			}
			return
		}
		if current.Message != nil {
			walk(current.Message)
			return
		}
		if !strings.EqualFold(current.MediaType, "TEXT") && current.MediaType != "" {
			return
		}
		reader := current.ReaderUTF8OrBinary()
		if reader == nil {
			return
		}
		remaining := maxSearchTextBytes - len(data)
		decoded, _ := io.ReadAll(io.LimitReader(reader, int64(remaining)+1))
		text := string(decoded)
		if strings.EqualFold(current.MediaSubType, "HTML") {
			text = stripHTMLTags(text)
		}
		appendText(text)
	}
	walk(&part)
	// EnsurePart returns a usable fallback part together with an error for
	// malformed MIME. Union only a bounded raw body in that case: headers were
	// already indexed above, and sanitizing the complete source before truncating
	// would multiply memory use for a large malformed message.
	if err != nil {
		remaining := maxSearchTextBytes - len(data)
		if remaining > 0 {
			body := rawMessageBody(raw)
			if len(body) > remaining {
				body = body[:remaining]
			}
			appendText(string(body))
		}
	}
	if len(data) == 0 {
		return boundedSearchText(nil, raw)
	}
	return boundedSearchText(nil, data)
}

func rawMessageBody(raw []byte) []byte {
	if index := bytes.Index(raw, []byte("\r\n\r\n")); index >= 0 {
		return raw[index+4:]
	}
	if index := bytes.Index(raw, []byte("\n\n")); index >= 0 {
		return raw[index+2:]
	}
	return raw
}
