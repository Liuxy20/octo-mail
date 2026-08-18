package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/jackc/pgx/v5"
	moxmessage "github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
)

const maxEnabledMailRules = 50

func (t *tenantScope) AgentMailRules(ctx context.Context, ownerPrincipalID, accountID int64) ([]directory.MailRule, error) {
	if err := t.requireOwnedAgentMailbox(ctx, ownerPrincipalID, accountID); err != nil {
		return nil, err
	}
	rows, err := t.s.Pool.Query(ctx,
		`SELECT id,account_id,name,enabled,priority,match_mode,conditions,match_from,match_subject,forward_targets,created_at,updated_at
		 FROM mail_rules WHERE account_id=$1 ORDER BY priority DESC,id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list mail rules: %w", err)
	}
	defer rows.Close()
	var rules []directory.MailRule
	for rows.Next() {
		rule, err := scanMailRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan mail rule: %w", err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list mail rules: %w", err)
	}
	return rules, nil
}

func (t *tenantScope) CreateAgentMailRule(ctx context.Context, ownerPrincipalID, accountID int64, input directory.MailRuleInput) (directory.MailRule, error) {
	input, err := normalizeMailRuleInput(input)
	if err != nil {
		return directory.MailRule{}, err
	}
	tx, err := t.beginOwnedAgentMailboxWrite(ctx, ownerPrincipalID, accountID)
	if err != nil {
		return directory.MailRule{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds
	if input.Enabled {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mail_rules WHERE account_id=$1 AND enabled`, accountID).Scan(&count); err != nil {
			return directory.MailRule{}, fmt.Errorf("count enabled mail rules: %w", err)
		}
		if count >= maxEnabledMailRules {
			return directory.MailRule{}, directory.ErrMailRuleLimit
		}
	}
	rule, err := scanMailRule(tx.QueryRow(ctx,
		`INSERT INTO mail_rules
		 (account_id,name,enabled,priority,match_mode,conditions,match_from,match_subject,forward_targets,created_by_principal_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING id,account_id,name,enabled,priority,match_mode,conditions,match_from,match_subject,forward_targets,created_at,updated_at`,
		accountID, input.Name, input.Enabled, input.Priority, input.MatchMode, mustJSON(input.Conditions), input.MatchFrom, input.MatchSubject,
		input.ForwardTargets, ownerPrincipalID))
	if err != nil {
		return directory.MailRule{}, fmt.Errorf("create mail rule: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return directory.MailRule{}, fmt.Errorf("commit mail rule: %w", err)
	}
	return rule, nil
}

func (t *tenantScope) UpdateAgentMailRule(ctx context.Context, ownerPrincipalID, accountID, ruleID int64, patch directory.MailRulePatch) (directory.MailRule, error) {
	tx, err := t.beginOwnedAgentMailboxWrite(ctx, ownerPrincipalID, accountID)
	if err != nil {
		return directory.MailRule{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds
	current, err := scanMailRule(tx.QueryRow(ctx,
		`SELECT id,account_id,name,enabled,priority,match_mode,conditions,match_from,match_subject,forward_targets,created_at,updated_at
		 FROM mail_rules WHERE account_id=$1 AND id=$2`, accountID, ruleID))
	if errors.Is(err, pgx.ErrNoRows) {
		return directory.MailRule{}, directory.ErrMailRuleNotFound
	}
	if err != nil {
		return directory.MailRule{}, fmt.Errorf("get mail rule: %w", err)
	}
	input := directory.MailRuleInput{
		Name: current.Name, Enabled: current.Enabled, Priority: current.Priority, MatchMode: current.MatchMode,
		Conditions: current.Conditions,
		MatchFrom:  current.MatchFrom, MatchSubject: current.MatchSubject,
		ForwardTargets: current.ForwardTargets,
	}
	if len(input.Conditions) == 0 {
		input.Conditions = legacyMailRuleConditions(input.MatchFrom, input.MatchSubject)
	}
	if patch.Name != nil {
		input.Name = *patch.Name
	}
	if patch.Enabled != nil {
		input.Enabled = *patch.Enabled
	}
	if patch.Priority != nil {
		input.Priority = *patch.Priority
	}
	if patch.MatchMode != nil {
		input.MatchMode = *patch.MatchMode
	}
	if patch.Conditions != nil {
		input.Conditions = *patch.Conditions
	}
	if patch.MatchFrom != nil {
		input.MatchFrom = *patch.MatchFrom
		if patch.Conditions == nil {
			input.Conditions = replaceLegacyMailRuleCondition(input.Conditions, "from", "equals", *patch.MatchFrom)
		}
	}
	if patch.MatchSubject != nil {
		input.MatchSubject = *patch.MatchSubject
		if patch.Conditions == nil {
			input.Conditions = replaceLegacyMailRuleCondition(input.Conditions, "subject", "contains", *patch.MatchSubject)
		}
	}
	if patch.ForwardTargets != nil {
		input.ForwardTargets = *patch.ForwardTargets
	}
	input, err = normalizeMailRuleInput(input)
	if err != nil {
		return directory.MailRule{}, err
	}
	if input.Enabled && !current.Enabled {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mail_rules WHERE account_id=$1 AND enabled`, accountID).Scan(&count); err != nil {
			return directory.MailRule{}, fmt.Errorf("count enabled mail rules: %w", err)
		}
		if count >= maxEnabledMailRules {
			return directory.MailRule{}, directory.ErrMailRuleLimit
		}
	}
	rule, err := scanMailRule(tx.QueryRow(ctx,
		`UPDATE mail_rules SET name=$3,enabled=$4,priority=$5,match_mode=$6,conditions=$7,match_from=$8,match_subject=$9,
		 forward_targets=$10,updated_at=now() WHERE account_id=$1 AND id=$2
		 RETURNING id,account_id,name,enabled,priority,match_mode,conditions,match_from,match_subject,forward_targets,created_at,updated_at`,
		accountID, ruleID, input.Name, input.Enabled, input.Priority, input.MatchMode, mustJSON(input.Conditions), input.MatchFrom,
		input.MatchSubject, input.ForwardTargets))
	if err != nil {
		return directory.MailRule{}, fmt.Errorf("update mail rule: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return directory.MailRule{}, fmt.Errorf("commit mail rule: %w", err)
	}
	return rule, nil
}

func (t *tenantScope) DeleteAgentMailRule(ctx context.Context, ownerPrincipalID, accountID, ruleID int64) error {
	tx, err := t.beginOwnedAgentMailboxWrite(ctx, ownerPrincipalID, accountID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds
	result, err := tx.Exec(ctx, `DELETE FROM mail_rules WHERE account_id=$1 AND id=$2`, accountID, ruleID)
	if err != nil {
		return fmt.Errorf("delete mail rule: %w", err)
	}
	if result.RowsAffected() == 0 {
		return directory.ErrMailRuleNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit mail rule deletion: %w", err)
	}
	return nil
}

func (t *tenantScope) AgentMailRuleExecutions(ctx context.Context, ownerPrincipalID, accountID int64, limit int) ([]directory.MailRuleExecution, error) {
	if err := t.requireOwnedAgentMailbox(ctx, ownerPrincipalID, accountID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := t.s.Pool.Query(ctx,
		`SELECT id,rule_id,source_email_id,status,target_results,hop_count,error_code,created_at,completed_at
		 FROM mail_rule_executions WHERE account_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`,
		accountID, limit)
	if err != nil {
		return nil, fmt.Errorf("list mail rule executions: %w", err)
	}
	defer rows.Close()
	var executions []directory.MailRuleExecution
	for rows.Next() {
		var execution directory.MailRuleExecution
		var targetResults []byte
		if err := rows.Scan(&execution.ID, &execution.RuleID, &execution.SourceEmailID,
			&execution.Status, &targetResults, &execution.HopCount, &execution.ErrorCode,
			&execution.CreatedAt, &execution.CompletedAt); err != nil {
			return nil, fmt.Errorf("scan mail rule execution: %w", err)
		}
		execution.TargetResults = append([]byte(nil), targetResults...)
		executions = append(executions, execution)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list mail rule executions: %w", err)
	}
	return executions, nil
}

func (t *tenantScope) requireOwnedAgentMailbox(ctx context.Context, ownerPrincipalID, accountID int64) error {
	var exists bool
	err := t.s.Pool.QueryRow(ctx,
		`SELECT true FROM accounts
		 WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND NOT disabled`,
		t.info.ID, accountID, ownerPrincipalID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return directory.ErrMailboxNotFound
	}
	if err != nil {
		return fmt.Errorf("resolve mail rule owner: %w", err)
	}
	return nil
}

func (t *tenantScope) beginOwnedAgentMailboxWrite(ctx context.Context, ownerPrincipalID, accountID int64) (pgx.Tx, error) {
	tx, err := t.s.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin mail rule write: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, accountID); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		return nil, fmt.Errorf("lock mail rule account: %w", err)
	}
	var exists bool
	err = tx.QueryRow(ctx,
		`SELECT true FROM accounts
		 WHERE tenant_id=$1 AND id=$2 AND owner_principal_id=$3 AND NOT disabled`,
		t.info.ID, accountID, ownerPrincipalID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		tx.Rollback(ctx) //nolint:errcheck
		return nil, directory.ErrMailboxNotFound
	}
	if err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		return nil, fmt.Errorf("resolve mail rule owner: %w", err)
	}
	return tx, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMailRule(row rowScanner) (directory.MailRule, error) {
	var rule directory.MailRule
	var conditions []byte
	err := row.Scan(&rule.ID, &rule.AccountID, &rule.Name, &rule.Enabled, &rule.Priority, &rule.MatchMode,
		&conditions, &rule.MatchFrom, &rule.MatchSubject, &rule.ForwardTargets, &rule.CreatedAt, &rule.UpdatedAt)
	if err == nil {
		err = json.Unmarshal(conditions, &rule.Conditions)
	}
	return rule, err
}

func normalizeMailRuleInput(input directory.MailRuleInput) (directory.MailRuleInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.MatchFrom = strings.TrimSpace(input.MatchFrom)
	input.MatchSubject = strings.TrimSpace(input.MatchSubject)
	input.MatchMode = strings.TrimSpace(input.MatchMode)
	if input.MatchMode == "" {
		input.MatchMode = "all"
	}
	if input.Name == "" || len(input.Name) > 100 || input.Priority < -1000 || input.Priority > 1000 ||
		(input.MatchMode != "all" && input.MatchMode != "any") {
		return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
	}
	if len(input.Conditions) == 0 {
		input.Conditions = legacyMailRuleConditions(input.MatchFrom, input.MatchSubject)
	}
	if len(input.Conditions) == 0 || len(input.Conditions) > 5 {
		return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
	}
	seenConditions := make(map[string]struct{}, len(input.Conditions))
	for i := range input.Conditions {
		condition := &input.Conditions[i]
		condition.Field = strings.TrimSpace(condition.Field)
		condition.Operator = strings.TrimSpace(condition.Operator)
		condition.Value = strings.TrimSpace(condition.Value)
		if !validMailRuleCondition(*condition) || len([]rune(condition.Value)) > 500 {
			return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
		}
		if condition.Field == "from" && condition.Operator == "equals" {
			address, err := parseMailRuleAddress(condition.Value)
			if err != nil {
				return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
			}
			condition.Value = address.Pack(false)
		}
		if _, exists := seenConditions[condition.Field]; exists {
			return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
		}
		seenConditions[condition.Field] = struct{}{}
	}
	if len(input.MatchSubject) > 500 {
		return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
	}
	if input.MatchFrom != "" {
		address, err := smtp.ParseAddress(input.MatchFrom)
		if err != nil {
			return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
		}
		input.MatchFrom = address.Pack(false)
	}
	if len(input.ForwardTargets) == 0 || len(input.ForwardTargets) > 5 {
		return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
	}
	seen := make(map[string]struct{}, len(input.ForwardTargets))
	targets := make([]string, 0, len(input.ForwardTargets))
	for _, raw := range input.ForwardTargets {
		address, err := smtp.ParseAddress(strings.TrimSpace(raw))
		if err != nil {
			return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
		}
		normalized := address.Pack(false)
		// SMTP local-parts are case-sensitive. ParseAddress canonicalizes the
		// domain, so exact comparison removes true duplicates without changing
		// standard mailbox semantics.
		key := normalized
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, normalized)
	}
	if len(targets) == 0 {
		return directory.MailRuleInput{}, directory.ErrMailRuleInvalid
	}
	input.ForwardTargets = targets
	return input, nil
}

func parseMailRuleAddress(value string) (smtp.Address, error) {
	address, err := smtp.ParseAddress(value)
	if err == nil {
		return address, nil
	}
	addresses, listErr := moxmessage.ParseAddressList(value)
	if listErr != nil || len(addresses) != 1 {
		return smtp.Address{}, err
	}
	return smtp.ParseAddress(addresses[0].User + "@" + addresses[0].Host)
}

func legacyMailRuleConditions(matchFrom, matchSubject string) []directory.MailRuleCondition {
	var conditions []directory.MailRuleCondition
	if strings.TrimSpace(matchFrom) != "" {
		conditions = append(conditions, directory.MailRuleCondition{Field: "from", Operator: "equals", Value: matchFrom})
	}
	if strings.TrimSpace(matchSubject) != "" {
		conditions = append(conditions, directory.MailRuleCondition{Field: "subject", Operator: "contains", Value: matchSubject})
	}
	return conditions
}

func replaceLegacyMailRuleCondition(conditions []directory.MailRuleCondition, field, operator, value string) []directory.MailRuleCondition {
	value = strings.TrimSpace(value)
	result := make([]directory.MailRuleCondition, 0, len(conditions)+1)
	replaced := false
	for _, condition := range conditions {
		if condition.Field != field {
			result = append(result, condition)
			continue
		}
		if !replaced && value != "" {
			result = append(result, directory.MailRuleCondition{Field: field, Operator: operator, Value: value})
		}
		replaced = true
	}
	if !replaced && value != "" {
		result = append(result, directory.MailRuleCondition{Field: field, Operator: operator, Value: value})
	}
	return result
}

func validMailRuleCondition(condition directory.MailRuleCondition) bool {
	switch condition.Field {
	case "from", "to", "subject", "body", "subject_or_body":
	default:
		return false
	}
	if condition.Operator != "contains" && condition.Operator != "not_contains" && condition.Operator != "equals" {
		return false
	}
	return condition.Value != ""
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

var _ directory.AgentMailRuleScope = (*tenantScope)(nil)
