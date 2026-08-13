package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

const emailChangeScanBatch = 256

type persistedChange struct {
	seq     store.ModSeq
	kind    uint8
	payload []byte
}

type changedEmail struct {
	id            int64
	existedBefore bool
}

// EmailChanges folds account change-log entries into stable Email identity
// transitions for JMAP Email/changes. The fold and returned state use one
// repeatable-read snapshot, preventing a concurrent delivery from being folded
// into newState without also appearing in the change set.
func (a *account) EmailChanges(ctx context.Context, since store.ModSeq, maxChanges int) (store.EmailChangeSet, error) {
	if maxChanges <= 0 {
		return store.EmailChangeSet{}, store.ErrCannotCalculateEmailChanges
	}
	result := store.EmailChangeSet{NewState: since}
	err := a.ReadTx(ctx, func(tx store.Tx) error {
		pt := tx.(*pgTx)
		var head int64
		if err := pt.tx.QueryRow(pt.ctx,
			`SELECT changelog_seq FROM accounts WHERE id=$1`, a.id).Scan(&head); err != nil {
			return fmt.Errorf("read email changes head: %w", err)
		}
		if since < 0 || int64(since) > head {
			return store.ErrCannotCalculateEmailChanges
		}

		var earliest sql.NullInt64
		if err := pt.tx.QueryRow(pt.ctx,
			`SELECT min(seq) FROM changelog WHERE account_id=$1`, a.id).Scan(&earliest); err != nil {
			return fmt.Errorf("read earliest email change: %w", err)
		}
		if earliest.Valid && int64(since) < earliest.Int64-1 {
			return store.ErrCannotCalculateEmailChanges
		}

		position := since
		seen := make(map[int64]struct{})
		existedAtSince := make(map[int64]bool)
		var ordered []int64
		for int64(position) < head {
			changes, err := loadPersistedChanges(pt, position, store.ModSeq(head), emailChangeScanBatch)
			if err != nil {
				return err
			}
			if len(changes) == 0 {
				return store.ErrCannotCalculateEmailChanges
			}
			stopped := false
			for _, change := range changes {
				impacts, err := changeEmailIDs(pt, change)
				if err != nil {
					return err
				}
				newCount := 0
				for _, impact := range impacts {
					if _, ok := seen[impact.id]; !ok {
						newCount++
					}
				}
				if len(seen)+newCount > maxChanges {
					if len(seen) == 0 {
						return store.ErrCannotCalculateEmailChanges
					}
					stopped = true
					break
				}
				for _, impact := range impacts {
					if _, ok := existedAtSince[impact.id]; !ok {
						existedAtSince[impact.id] = impact.existedBefore
					}
					if _, ok := seen[impact.id]; ok {
						continue
					}
					seen[impact.id] = struct{}{}
					ordered = append(ordered, impact.id)
				}
				position = change.seq
			}
			if stopped {
				break
			}
		}

		result.NewState = position
		result.HasMore = int64(position) < head
		for _, id := range ordered {
			oldExists, err := emailExistsAt(pt, id, since)
			if err != nil {
				return err
			}
			oldExists = oldExists || existedAtSince[id]
			newExists, err := emailExistsAt(pt, id, position)
			if err != nil {
				return err
			}
			switch {
			case !oldExists && newExists:
				result.Created = append(result.Created, id)
			case oldExists && newExists:
				result.Updated = append(result.Updated, id)
			case oldExists && !newExists:
				result.Destroyed = append(result.Destroyed, id)
			}
		}
		return nil
	})
	return result, err
}

func loadPersistedChanges(pt *pgTx, after, head store.ModSeq, limit int) ([]persistedChange, error) {
	rows, err := pt.tx.Query(pt.ctx,
		`SELECT seq, kind, payload FROM changelog
		 WHERE account_id=$1 AND seq>$2 AND seq<=$3
		 ORDER BY seq LIMIT $4`,
		pt.acc.id, int64(after), int64(head), limit)
	if err != nil {
		return nil, fmt.Errorf("query email changes: %w", err)
	}
	defer rows.Close()
	var out []persistedChange
	for rows.Next() {
		var seq int64
		var kind int16
		var payload []byte
		if err := rows.Scan(&seq, &kind, &payload); err != nil {
			return nil, fmt.Errorf("scan email change: %w", err)
		}
		out = append(out, persistedChange{seq: store.ModSeq(seq), kind: uint8(kind), payload: payload})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate email changes: %w", err)
	}
	return out, nil
}

func changeEmailIDs(pt *pgTx, change persistedChange) ([]changedEmail, error) {
	decoded, err := decodeChange(change.kind, change.payload)
	if err != nil {
		return nil, fmt.Errorf("decode email change at %d: %w", change.seq, err)
	}
	switch value := decoded.(type) {
	case store.ChangeAddUID:
		if id := persistedEmailID(value.EmailID, value.MsgID); id > 0 {
			return []changedEmail{{id: id, existedBefore: value.EmailExistedBefore}}, nil
		}
		id, err := emailIDByMailboxUID(pt, value.MailboxID, value.UID)
		if err != nil {
			return nil, err
		}
		return []changedEmail{{id: id, existedBefore: value.EmailExistedBefore}}, nil
	case store.ChangeFlags:
		if id := persistedEmailID(value.EmailID, value.MsgID); id > 0 {
			return []changedEmail{{id: id, existedBefore: true}}, nil
		}
		id, err := emailIDByMailboxUID(pt, value.MailboxID, value.UID)
		if err != nil {
			return nil, err
		}
		return []changedEmail{{id: id, existedBefore: true}}, nil
	case store.ChangeRemoveUIDs:
		ids := make([]changedEmail, 0, len(value.MsgIDs))
		seen := make(map[int64]struct{})
		for i, messageID := range value.MsgIDs {
			id := int64(0)
			if i < len(value.EmailIDs) {
				id = value.EmailIDs[i]
			}
			if id <= 0 {
				if err := pt.tx.QueryRow(pt.ctx,
					`SELECT COALESCE(email_id, id) FROM messages
					 WHERE account_id=$1 AND id=$2`, pt.acc.id, messageID).Scan(&id); err != nil {
					return nil, store.ErrCannotCalculateEmailChanges
				}
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, changedEmail{id: id, existedBefore: true})
		}
		return ids, nil
	default:
		return nil, nil
	}
}

func persistedEmailID(emailID, messageID int64) int64 {
	if emailID > 0 {
		return emailID
	}
	return messageID
}

func emailIDByMailboxUID(pt *pgTx, mailboxID int64, uid store.UID) (int64, error) {
	var id int64
	if err := pt.tx.QueryRow(pt.ctx,
		`SELECT COALESCE(email_id, id) FROM messages
		 WHERE account_id=$1 AND mailbox_id=$2 AND uid=$3`,
		pt.acc.id, mailboxID, int64(uid)).Scan(&id); err != nil {
		return 0, store.ErrCannotCalculateEmailChanges
	}
	return id, nil
}

func emailExistsAt(pt *pgTx, emailID int64, state store.ModSeq) (bool, error) {
	var exists bool
	if err := pt.tx.QueryRow(pt.ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM messages
		   WHERE account_id=$1 AND (id=$2 OR email_id=$2)
		     AND createseq<=$3
		     AND (NOT expunged OR modseq>$3)
		 )`, pt.acc.id, emailID, int64(state)).Scan(&exists); err != nil {
		return false, fmt.Errorf("evaluate email existence at state: %w", err)
	}
	return exists, nil
}
