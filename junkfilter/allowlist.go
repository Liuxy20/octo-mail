package junkfilter

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/mjl-/mox/smtp"
)

// NormalizeSenderAddress canonicalizes one exact mailbox address for storage
// and comparison. Display names and groups are intentionally not accepted.
func NormalizeSenderAddress(value string) (string, error) {
	address, err := smtp.ParseAddress(strings.TrimSpace(value))
	if err != nil || address.Localpart == "" || address.Domain.ASCII == "" {
		return "", errors.New("invalid sender address")
	}
	return strings.ToLower(address.String()), nil
}

// SenderAllowed reports whether this exact sender is explicitly trusted by the
// recipient account. Authentication is checked by the SMTP caller before this
// result is allowed to bypass content classification.
func (m *Manager) SenderAllowed(ctx context.Context, accountID int64, sender string) (bool, error) {
	normalized, err := NormalizeSenderAddress(sender)
	if err != nil {
		return false, nil
	}
	var exists bool
	err = m.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM junk_sender_allowlist WHERE account_id=$1 AND sender_address=$2)`,
		accountID, normalized).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return exists, err
}
