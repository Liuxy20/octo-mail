package webapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
)

type mailRuleInfo struct {
	ID             string                        `json:"id"`
	Name           string                        `json:"name"`
	Enabled        bool                          `json:"enabled"`
	Priority       int                           `json:"priority"`
	MatchMode      string                        `json:"matchMode"`
	Conditions     []directory.MailRuleCondition `json:"conditions"`
	MatchFrom      string                        `json:"matchFrom,omitempty"`
	MatchSubject   string                        `json:"matchSubject,omitempty"`
	ForwardTargets []string                      `json:"forwardTargets"`
	CreatedAt      string                        `json:"createdAt"`
	UpdatedAt      string                        `json:"updatedAt"`
}

type createMailRuleRequest struct {
	Name           string                        `json:"name"`
	Enabled        *bool                         `json:"enabled"`
	Priority       int                           `json:"priority"`
	MatchMode      string                        `json:"matchMode"`
	Conditions     []directory.MailRuleCondition `json:"conditions"`
	MatchFrom      string                        `json:"matchFrom"`
	MatchSubject   string                        `json:"matchSubject"`
	ForwardTargets []string                      `json:"forwardTargets"`
}

type updateMailRuleRequest struct {
	Name           *string                        `json:"name"`
	Enabled        *bool                          `json:"enabled"`
	Priority       *int                           `json:"priority"`
	MatchMode      *string                        `json:"matchMode"`
	Conditions     *[]directory.MailRuleCondition `json:"conditions"`
	MatchFrom      *string                        `json:"matchFrom"`
	MatchSubject   *string                        `json:"matchSubject"`
	ForwardTargets *[]string                      `json:"forwardTargets"`
}

type mailRuleExecutionInfo struct {
	ID            string          `json:"id"`
	RuleID        string          `json:"ruleId"`
	SourceEmailID string          `json:"sourceEmailId"`
	Status        string          `json:"status"`
	TargetResults json.RawMessage `json:"targetResults"`
	HopCount      int             `json:"hopCount"`
	ErrorCode     string          `json:"errorCode,omitempty"`
	CreatedAt     string          `json:"createdAt"`
	CompletedAt   string          `json:"completedAt,omitempty"`
}

func (s *Server) listAgentMailRules(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	mailboxID, err := parsePositivePathID(r, "mailboxId", "invalid_mailbox")
	if err != nil {
		return 0, nil, err
	}
	if err := s.requireAgentMailboxInSpace(ctx, a, mailboxID); err != nil {
		return 0, nil, err
	}
	scope, err := agentMailRuleScope(a)
	if err != nil {
		return 0, nil, err
	}
	rules, err := scope.AgentMailRules(ctx, a.principal.ID, mailboxID)
	if err != nil {
		return 0, nil, mailRuleStatusError(err)
	}
	items := make([]mailRuleInfo, 0, len(rules))
	for _, rule := range rules {
		items = append(items, toMailRuleInfo(rule))
	}
	return http.StatusOK, map[string]any{"rules": items}, nil
}

func (s *Server) createAgentMailRule(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if !a.humanAuthenticated {
		return 0, nil, errStatus(http.StatusForbidden, "human_owner_required", "rule changes require the human mailbox owner")
	}
	mailboxID, err := parsePositivePathID(r, "mailboxId", "invalid_mailbox")
	if err != nil {
		return 0, nil, err
	}
	if err := s.requireAgentMailboxInSpace(ctx, a, mailboxID); err != nil {
		return 0, nil, err
	}
	var input createMailRuleRequest
	if err := decode(r, &input); err != nil {
		return 0, nil, err
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	scope, err := agentMailRuleScope(a)
	if err != nil {
		return 0, nil, err
	}
	rule, err := scope.CreateAgentMailRule(ctx, a.principal.ID, mailboxID, directory.MailRuleInput{
		Name: input.Name, Enabled: enabled, Priority: input.Priority, MatchMode: input.MatchMode,
		Conditions: input.Conditions,
		MatchFrom:  input.MatchFrom, MatchSubject: input.MatchSubject,
		ForwardTargets: input.ForwardTargets,
	})
	if err != nil {
		return 0, nil, mailRuleStatusError(err)
	}
	return http.StatusCreated, toMailRuleInfo(rule), nil
}

func (s *Server) updateAgentMailRule(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if !a.humanAuthenticated {
		return 0, nil, errStatus(http.StatusForbidden, "human_owner_required", "rule changes require the human mailbox owner")
	}
	mailboxID, err := parsePositivePathID(r, "mailboxId", "invalid_mailbox")
	if err != nil {
		return 0, nil, err
	}
	if err := s.requireAgentMailboxInSpace(ctx, a, mailboxID); err != nil {
		return 0, nil, err
	}
	ruleID, err := parsePositivePathID(r, "ruleId", "invalid_rule")
	if err != nil {
		return 0, nil, err
	}
	var input updateMailRuleRequest
	if err := decode(r, &input); err != nil {
		return 0, nil, err
	}
	if input.Name == nil && input.Enabled == nil && input.Priority == nil && input.MatchMode == nil && input.Conditions == nil && input.MatchFrom == nil &&
		input.MatchSubject == nil && input.ForwardTargets == nil {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_rule", "at least one rule field is required")
	}
	scope, err := agentMailRuleScope(a)
	if err != nil {
		return 0, nil, err
	}
	rule, err := scope.UpdateAgentMailRule(ctx, a.principal.ID, mailboxID, ruleID, directory.MailRulePatch{
		Name: input.Name, Enabled: input.Enabled, Priority: input.Priority, MatchMode: input.MatchMode,
		Conditions: input.Conditions,
		MatchFrom:  input.MatchFrom, MatchSubject: input.MatchSubject,
		ForwardTargets: input.ForwardTargets,
	})
	if err != nil {
		return 0, nil, mailRuleStatusError(err)
	}
	return http.StatusOK, toMailRuleInfo(rule), nil
}

func (s *Server) deleteAgentMailRule(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if !a.humanAuthenticated {
		return 0, nil, errStatus(http.StatusForbidden, "human_owner_required", "rule changes require the human mailbox owner")
	}
	mailboxID, err := parsePositivePathID(r, "mailboxId", "invalid_mailbox")
	if err != nil {
		return 0, nil, err
	}
	if err := s.requireAgentMailboxInSpace(ctx, a, mailboxID); err != nil {
		return 0, nil, err
	}
	ruleID, err := parsePositivePathID(r, "ruleId", "invalid_rule")
	if err != nil {
		return 0, nil, err
	}
	scope, err := agentMailRuleScope(a)
	if err != nil {
		return 0, nil, err
	}
	if err := scope.DeleteAgentMailRule(ctx, a.principal.ID, mailboxID, ruleID); err != nil {
		return 0, nil, mailRuleStatusError(err)
	}
	return http.StatusNoContent, nil, nil
}

func (s *Server) listAgentMailRuleExecutions(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	mailboxID, err := parsePositivePathID(r, "mailboxId", "invalid_mailbox")
	if err != nil {
		return 0, nil, err
	}
	if err := s.requireAgentMailboxInSpace(ctx, a, mailboxID); err != nil {
		return 0, nil, err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 100 {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 100")
		}
		limit = parsed
	}
	scope, err := agentMailRuleScope(a)
	if err != nil {
		return 0, nil, err
	}
	executions, err := scope.AgentMailRuleExecutions(ctx, a.principal.ID, mailboxID, limit)
	if err != nil {
		return 0, nil, mailRuleStatusError(err)
	}
	items := make([]mailRuleExecutionInfo, 0, len(executions))
	for _, execution := range executions {
		item := mailRuleExecutionInfo{
			ID: strconv.FormatInt(execution.ID, 10), RuleID: strconv.FormatInt(execution.RuleID, 10),
			SourceEmailID: "E" + strconv.FormatInt(execution.SourceEmailID, 10), Status: execution.Status,
			TargetResults: json.RawMessage(execution.TargetResults), HopCount: execution.HopCount,
			ErrorCode: execution.ErrorCode, CreatedAt: execution.CreatedAt.UTC().Format(time.RFC3339),
		}
		if execution.CompletedAt != nil {
			item.CompletedAt = execution.CompletedAt.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	return http.StatusOK, map[string]any{"executions": items}, nil
}

func agentMailRuleScope(a authCtx) (directory.AgentMailRuleScope, error) {
	scope, ok := a.scope.(directory.AgentMailRuleScope)
	if !ok {
		return nil, errStatus(http.StatusNotImplemented, "mail_rules_unavailable", "mail rules are not available")
	}
	return scope, nil
}

func parsePositivePathID(r *http.Request, name, code string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, errStatus(http.StatusBadRequest, code, name+" is invalid")
	}
	return id, nil
}

func toMailRuleInfo(rule directory.MailRule) mailRuleInfo {
	return mailRuleInfo{
		ID: strconv.FormatInt(rule.ID, 10), Name: rule.Name, Enabled: rule.Enabled,
		Priority: rule.Priority, MatchMode: rule.MatchMode, Conditions: effectiveMailRuleConditions(rule), MatchFrom: rule.MatchFrom, MatchSubject: rule.MatchSubject,
		ForwardTargets: rule.ForwardTargets, CreatedAt: rule.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: rule.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func effectiveMailRuleConditions(rule directory.MailRule) []directory.MailRuleCondition {
	if len(rule.Conditions) > 0 {
		return rule.Conditions
	}
	conditions := make([]directory.MailRuleCondition, 0, 2)
	if rule.MatchFrom != "" {
		conditions = append(conditions, directory.MailRuleCondition{Field: "from", Operator: "equals", Value: rule.MatchFrom})
	}
	if rule.MatchSubject != "" {
		conditions = append(conditions, directory.MailRuleCondition{Field: "subject", Operator: "contains", Value: rule.MatchSubject})
	}
	return conditions
}

func mailRuleStatusError(err error) error {
	switch {
	case errors.Is(err, directory.ErrMailboxNotFound):
		return errStatus(http.StatusNotFound, "mailbox_not_owned", "mailbox was not found")
	case errors.Is(err, directory.ErrMailRuleNotFound):
		return errStatus(http.StatusNotFound, "rule_not_found", "mail rule was not found")
	case errors.Is(err, directory.ErrMailRuleInvalid):
		return errStatus(http.StatusBadRequest, "invalid_rule", "rule fields are invalid")
	case errors.Is(err, directory.ErrMailRuleLimit):
		return errStatus(http.StatusConflict, "rule_limit", "enabled mail rule limit reached")
	default:
		return err
	}
}
