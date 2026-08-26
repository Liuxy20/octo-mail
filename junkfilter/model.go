package junkfilter

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	modelMagic       = "octo-junk-model"
	modelFormat      = 1
	modelInsertBatch = 1000
	maxModelWords    = 2_000_000
	defaultModelPath = "models/shared-junk-v1.csv.gz"
)

// modelFiles contains the versioned default shared model distributed with the
// server. It contains aggregate hashed feature counters, not raw messages.
//
//go:embed models
var modelFiles embed.FS

// ModelInfo describes a portable shared Bayesian model package.
type ModelInfo struct {
	Version string
	Hams    int64
	Spams   int64
	Words   int64
}

// BootstrapDefaultModel imports the model shipped with the binary when the
// deployment-wide model is empty. Existing operator training always wins.
func (m *Manager) BootstrapDefaultModel(ctx context.Context) (bool, ModelInfo, error) {
	model, err := modelFiles.Open(defaultModelPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, ModelInfo{}, nil
	}
	if err != nil {
		return false, ModelInfo{}, fmt.Errorf("read bundled shared junk model: %w", err)
	}
	defer model.Close()
	return m.ImportGlobalModelIfEmpty(ctx, model)
}

// ImportGlobalModelIfEmpty transactionally imports a gzip-compressed model
// package. It is safe for concurrent startup: table locks serialize the empty
// check and import, and malformed/truncated packages roll back completely.
func (m *Manager) ImportGlobalModelIfEmpty(ctx context.Context, r io.Reader) (imported bool, info ModelInfo, err error) {
	err = pgx.BeginFunc(ctx, m.Pool, func(tx pgx.Tx) error {
		// Global training does not use an account lock. Lock its three tables for
		// this one-time bootstrap so a concurrent node or operator import cannot
		// observe or create a partial model.
		if _, err := tx.Exec(ctx,
			`LOCK TABLE junk_global_learns, junk_global_totals, junk_global_words IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return fmt.Errorf("lock shared junk model: %w", err)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM junk_global_learns) OR
			EXISTS (SELECT 1 FROM junk_global_totals) OR
			EXISTS (SELECT 1 FROM junk_global_words)`).Scan(&exists); err != nil {
			return fmt.Errorf("check shared junk model: %w", err)
		}
		if exists {
			return nil
		}

		decoded, err := gzip.NewReader(r)
		if err != nil {
			return fmt.Errorf("open shared junk model: %w", err)
		}
		defer decoded.Close()
		reader := csv.NewReader(decoded)
		reader.FieldsPerRecord = -1
		info, err = readModelHeader(reader)
		if err != nil {
			return err
		}

		words := make([]string, 0, modelInsertBatch)
		hams := make([]int64, 0, modelInsertBatch)
		spams := make([]int64, 0, modelInsertBatch)
		var rows int64
		flush := func() error {
			if len(words) == 0 {
				return nil
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO junk_global_words (word,ham,spam)
				 SELECT * FROM unnest($1::text[], $2::bigint[], $3::bigint[])`,
				words, hams, spams)
			words = words[:0]
			hams = hams[:0]
			spams = spams[:0]
			return err
		}
		for {
			record, err := reader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("read shared junk model row %d: %w", rows+1, err)
			}
			if len(record) != 3 || !validModelFeature(record[0]) {
				return fmt.Errorf("invalid shared junk model row %d", rows+1)
			}
			ham, err := parseModelCount(record[1], "ham", info.Hams)
			if err != nil {
				return fmt.Errorf("shared junk model row %d: %w", rows+1, err)
			}
			spam, err := parseModelCount(record[2], "spam", info.Spams)
			if err != nil {
				return fmt.Errorf("shared junk model row %d: %w", rows+1, err)
			}
			if ham == 0 && spam == 0 {
				return fmt.Errorf("shared junk model row %d has no counts", rows+1)
			}
			words = append(words, record[0])
			hams = append(hams, ham)
			spams = append(spams, spam)
			rows++
			if len(words) == modelInsertBatch {
				if err := flush(); err != nil {
					return fmt.Errorf("insert shared junk model: %w", err)
				}
			}
		}
		if rows != info.Words {
			return fmt.Errorf("shared junk model word count = %d, want %d", rows, info.Words)
		}
		if err := flush(); err != nil {
			return fmt.Errorf("insert shared junk model: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO junk_global_totals (singleton,hams,spams) VALUES (true,$1,$2)`,
			info.Hams, info.Spams); err != nil {
			return fmt.Errorf("insert shared junk totals: %w", err)
		}
		imported = true
		return nil
	})
	return imported, info, err
}

func readModelHeader(reader *csv.Reader) (ModelInfo, error) {
	record, err := reader.Read()
	if err != nil {
		return ModelInfo{}, fmt.Errorf("read shared junk model header: %w", err)
	}
	if len(record) != 6 || record[0] != modelMagic {
		return ModelInfo{}, errors.New("invalid shared junk model header")
	}
	format, err := strconv.Atoi(record[1])
	if err != nil || format != modelFormat {
		return ModelInfo{}, fmt.Errorf("unsupported shared junk model format %q", record[1])
	}
	info := ModelInfo{Version: strings.TrimSpace(record[2])}
	if info.Version == "" || len(info.Version) > 128 {
		return ModelInfo{}, errors.New("invalid shared junk model version")
	}
	if info.Hams, err = parseModelCount(record[3], "total ham", int64(^uint64(0)>>1)); err != nil {
		return ModelInfo{}, err
	}
	if info.Spams, err = parseModelCount(record[4], "total spam", int64(^uint64(0)>>1)); err != nil {
		return ModelInfo{}, err
	}
	if info.Words, err = parseModelCount(record[5], "word", maxModelWords); err != nil {
		return ModelInfo{}, err
	}
	if info.Hams == 0 || info.Spams == 0 || info.Words == 0 {
		return ModelInfo{}, errors.New("shared junk model totals must be positive")
	}
	return info, nil
}

func validModelFeature(feature string) bool {
	if len(feature) != sha256.Size*2 {
		return false
	}
	for _, c := range feature {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func parseModelCount(value, name string, max int64) (int64, error) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 || n > max {
		return 0, fmt.Errorf("invalid shared junk model %s count %q", name, value)
	}
	return n, nil
}

// ExportGlobalModel writes the current deployment-wide counters as one portable
// gzip package. It is an offline release helper; no raw corpus content is read.
func (m *Manager) ExportGlobalModel(ctx context.Context, w io.Writer, version string) (ModelInfo, error) {
	version = strings.TrimSpace(version)
	if version == "" || len(version) > 128 {
		return ModelInfo{}, errors.New("model version must contain 1-128 characters")
	}
	tx, err := m.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ModelInfo{}, err
	}
	defer tx.Rollback(ctx)

	info := ModelInfo{Version: version}
	if err := tx.QueryRow(ctx,
		`SELECT hams,spams,(SELECT count(*) FROM junk_global_words)
		 FROM junk_global_totals WHERE singleton=true`).Scan(&info.Hams, &info.Spams, &info.Words); err != nil {
		return ModelInfo{}, fmt.Errorf("read shared junk model totals: %w", err)
	}
	if info.Hams == 0 || info.Spams == 0 || info.Words == 0 {
		return ModelInfo{}, errors.New("shared junk model is empty")
	}

	compressed := gzip.NewWriter(w)
	csvWriter := csv.NewWriter(compressed)
	header := []string{modelMagic, strconv.Itoa(modelFormat), info.Version,
		strconv.FormatInt(info.Hams, 10), strconv.FormatInt(info.Spams, 10), strconv.FormatInt(info.Words, 10)}
	if err := csvWriter.Write(header); err != nil {
		return ModelInfo{}, err
	}
	rows, err := tx.Query(ctx, `SELECT word,ham,spam FROM junk_global_words ORDER BY word`)
	if err != nil {
		return ModelInfo{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var word string
		var ham, spam int64
		if err := rows.Scan(&word, &ham, &spam); err != nil {
			return ModelInfo{}, err
		}
		if !validModelFeature(word) {
			return ModelInfo{}, errors.New("shared junk model contains a non-hashed feature")
		}
		if err := csvWriter.Write([]string{word, strconv.FormatInt(ham, 10), strconv.FormatInt(spam, 10)}); err != nil {
			return ModelInfo{}, err
		}
	}
	if err := rows.Err(); err != nil {
		return ModelInfo{}, err
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return ModelInfo{}, err
	}
	if err := compressed.Close(); err != nil {
		return ModelInfo{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ModelInfo{}, err
	}
	return info, nil
}
