package postgres

import "fmt"

func (pt *pgTx) JunkAllowedSenders() ([]string, error) {
	rows, err := pt.tx.Query(pt.ctx,
		`SELECT sender_address FROM junk_sender_allowlist WHERE account_id=$1 ORDER BY sender_address`,
		pt.acc.id)
	if err != nil {
		return nil, fmt.Errorf("list junk sender allowlist: %w", err)
	}
	defer rows.Close()

	addresses := []string{}
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			return nil, fmt.Errorf("scan junk sender allowlist: %w", err)
		}
		addresses = append(addresses, address)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate junk sender allowlist: %w", err)
	}
	return addresses, nil
}

func (pt *pgTx) AddJunkAllowedSender(address string) error {
	if !pt.write {
		return fmt.Errorf("add junk sender allowlist: read-only transaction")
	}
	_, err := pt.tx.Exec(pt.ctx,
		`INSERT INTO junk_sender_allowlist (account_id, sender_address) VALUES ($1,$2)
		 ON CONFLICT (account_id, sender_address) DO NOTHING`,
		pt.acc.id, address)
	if err != nil {
		return fmt.Errorf("add junk sender allowlist: %w", err)
	}
	return nil
}

func (pt *pgTx) RemoveJunkAllowedSender(address string) error {
	if !pt.write {
		return fmt.Errorf("remove junk sender allowlist: read-only transaction")
	}
	_, err := pt.tx.Exec(pt.ctx,
		`DELETE FROM junk_sender_allowlist WHERE account_id=$1 AND sender_address=$2`,
		pt.acc.id, address)
	if err != nil {
		return fmt.Errorf("remove junk sender allowlist: %w", err)
	}
	return nil
}
