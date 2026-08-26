package webapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	moxmessage "github.com/mjl-/mox/message"
)

func junkAllowlistTx(tx store.Tx) (store.JunkSenderAllowlistTx, error) {
	allowlist, ok := tx.(store.JunkSenderAllowlistTx)
	if !ok {
		return nil, errStatus(http.StatusNotImplemented, "junk_allowlist_unavailable", "junk sender allowlist is not available")
	}
	return allowlist, nil
}

func requireHumanOwner(a authCtx) error {
	if a.agentCredentialID > 0 {
		return errStatus(http.StatusForbidden, "human_owner_required", "junk sender allowlist changes require the human mailbox owner")
	}
	return nil
}

func normalizeStoredFrom(raw []byte) (string, error) {
	address, _, _, err := moxmessage.From(nil, false, bytes.NewReader(raw), nil)
	if err != nil || address.Localpart == "" || address.Domain.ASCII == "" {
		return "", errStatus(http.StatusUnprocessableEntity, "sender_unavailable", "message does not contain one valid sender address")
	}
	return strings.ToLower(address.String()), nil
}

// POST /webapi/v0/messages/{id}/not-junk
//
// Restores a stored Junk message to Inbox and trusts its immutable From address
// for this account. The allowlist insertion and mailbox mutation share the
// account transaction, so callers never observe a half-applied owner action.
func (s *Server) restoreNotJunk(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if err := requireHumanOwner(a); err != nil {
		return 0, nil, err
	}
	id := r.PathValue("id")

	var source store.Message
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		messages, err := loadGroup(tx, a.acc, id)
		if err != nil {
			return err
		}
		source = messages[0]
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	reader := a.acc.MessageReader(ctx, source)
	raw, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return 0, nil, internalErr("message_read_failed", errors.Join(readErr, closeErr))
	}
	sender, err := normalizeStoredFrom(raw)
	if err != nil {
		return 0, nil, err
	}

	err = a.acc.Tx(ctx, func(tx store.Tx) error {
		allowlist, err := junkAllowlistTx(tx)
		if err != nil {
			return err
		}
		messages, err := loadGroup(tx, a.acc, id)
		if err != nil {
			return err
		}
		mailboxes := mailboxNames(tx, a.acc)
		inbox, err := a.acc.MailboxFind(tx, "Inbox")
		if err != nil {
			return err
		}
		if inbox == nil {
			created, _, err := a.acc.MailboxEnsure(tx, "Inbox", true, store.SpecialUse{}, nil)
			if err != nil {
				return err
			}
			inbox = &created
		}

		var junkRows []store.Message
		inInbox := false
		for i := range messages {
			message := messages[i]
			if strings.EqualFold(mailboxes[message.MailboxID], "Junk") {
				junkRows = append(junkRows, message)
			}
			if message.MailboxID == inbox.ID {
				inInbox = true
				if message.Junk || !message.Notjunk {
					message.Junk = false
					message.Notjunk = true
					if err := tx.Update(&message); err != nil {
						return err
					}
				}
			}
		}
		if len(junkRows) == 0 {
			return errStatus(http.StatusConflict, "not_in_junk", "message is not in Junk")
		}
		if !inInbox {
			copySource := junkRows[0]
			copySource.Junk = false
			copySource.Notjunk = true
			if _, _, err := a.acc.AddSibling(tx, copySource, inbox); err != nil {
				return err
			}
		}
		for i := range junkRows {
			junkMailbox, err := mailboxByID(tx, a.acc, junkRows[i].MailboxID)
			if err != nil {
				return err
			}
			if _, _, err := a.acc.MessageRemove(tx, 0, junkMailbox, store.RemoveOpts{Expunge: true}, junkRows[i]); err != nil {
				return err
			}
		}
		return allowlist.AddJunkAllowedSender(sender)
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"updated": id, "senderAddress": sender}, nil
}

func (s *Server) listJunkAllowedSenders(ctx context.Context, a authCtx, _ *http.Request) (int, any, error) {
	if err := requireHumanOwner(a); err != nil {
		return 0, nil, err
	}
	var addresses []string
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		allowlist, err := junkAllowlistTx(tx)
		if err != nil {
			return err
		}
		addresses, err = allowlist.JunkAllowedSenders()
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"addresses": addresses}, nil
}

func (s *Server) removeJunkAllowedSender(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if err := requireHumanOwner(a); err != nil {
		return 0, nil, err
	}
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	if address == "" {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_address", "sender address is required")
	}
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		allowlist, err := junkAllowlistTx(tx)
		if err != nil {
			return err
		}
		return allowlist.RemoveJunkAllowedSender(address)
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}
