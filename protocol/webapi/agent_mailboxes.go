package webapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
)

type agentMailboxInfo struct {
	ID               string                      `json:"id"`
	Address          string                      `json:"address"`
	BotID            string                      `json:"botId,omitempty"`
	BotProfile       string                      `json:"botProfile,omitempty"`
	AgentName        string                      `json:"agentName,omitempty"`
	ConnectState     string                      `json:"connectState"`
	OutboundMode     directory.AgentOutboundMode `json:"outboundMode"`
	AutoReplyEnabled bool                        `json:"autoReplyEnabled"` // Deprecated compatibility projection.
	Deletable        bool                        `json:"deletable"`
}

type createAgentMailboxRequest struct {
	Localpart string `json:"localpart"`
}

type updateAgentMailboxAutomationRequest struct {
	OutboundMode     directory.AgentOutboundMode `json:"outboundMode"`
	AutoReplyEnabled *bool                       `json:"autoReplyEnabled,omitempty"`
}

func toAgentMailboxInfo(mailbox directory.AgentMailbox) agentMailboxInfo {
	agentName := mailbox.BotProfile
	if agentName == "" {
		agentName = mailbox.BotID
	}
	connectState := mailbox.ConnectState
	if connectState == "" {
		connectState = "unconnected"
	}
	outboundMode := mailbox.OutboundMode
	if !outboundMode.Valid() {
		outboundMode = directory.AgentOutboundModeManualConfirmation
	}
	return agentMailboxInfo{
		ID:               strconv.FormatInt(mailbox.ID, 10),
		Address:          mailbox.Address,
		BotID:            mailbox.BotID,
		BotProfile:       mailbox.BotProfile,
		AgentName:        agentName,
		ConnectState:     connectState,
		OutboundMode:     outboundMode,
		AutoReplyEnabled: outboundMode == directory.AgentOutboundModeAutomaticSend,
		Deletable:        mailbox.Deletable,
	}
}

func (s *Server) requireAgentMailboxInSpace(ctx context.Context, a authCtx, mailboxID int64) error {
	if !a.humanAuthenticated || a.spaceID == "" {
		return errStatus(http.StatusForbidden, "space_required", "Agent mailbox management requires an authenticated Space")
	}
	mailboxes, err := a.scope.AgentMailboxes(ctx, a.principal.ID, a.spaceID)
	if err != nil {
		return err
	}
	for _, mailbox := range mailboxes {
		if mailbox.ID == mailboxID {
			return nil
		}
	}
	return errStatus(http.StatusForbidden, "mailbox_not_owned", "mailbox is not registered in the current Space")
}

func (s *Server) updateAgentMailboxAutomation(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if !a.humanAuthenticated {
		return 0, nil, errStatus(http.StatusForbidden, "human_owner_required", "automation changes require the human mailbox owner")
	}
	mailboxID, err := parsePositivePathID(r, "id", "invalid_mailbox")
	if err != nil {
		return 0, nil, err
	}
	var input updateAgentMailboxAutomationRequest
	if err := decode(r, &input); err != nil {
		return 0, nil, err
	}
	mode, err := resolveOutboundMode(input.OutboundMode, input.AutoReplyEnabled)
	if err != nil {
		return 0, nil, err
	}
	if err := s.requireAgentMailboxInSpace(ctx, a, mailboxID); err != nil {
		return 0, nil, err
	}
	dir, err := s.agentAuthorizationDirectory()
	if err != nil {
		return 0, nil, err
	}
	if err := dir.SetAgentOutboundMode(ctx, a.principal.ID, mailboxID, a.spaceID, mode); err != nil {
		switch {
		case errors.Is(err, directory.ErrMailboxNotFound):
			return 0, nil, errStatus(http.StatusForbidden, "mailbox_not_owned", "mailbox is not owned by the current user")
		case errors.Is(err, directory.ErrAgentBindingNotFound):
			return 0, nil, errStatus(http.StatusConflict, "mailbox_not_connected", "mailbox has no active Agent connection")
		default:
			return 0, nil, err
		}
	}
	mailboxes, err := a.scope.AgentMailboxes(ctx, a.principal.ID, a.spaceID)
	if err != nil {
		return 0, nil, err
	}
	for _, mailbox := range mailboxes {
		if mailbox.ID == mailboxID {
			return http.StatusOK, toAgentMailboxInfo(mailbox), nil
		}
	}
	return 0, nil, errStatus(http.StatusNotFound, "mailbox_not_found", "mailbox was not found")
}

func resolveOutboundMode(mode directory.AgentOutboundMode, legacy *bool) (directory.AgentOutboundMode, error) {
	if mode.Valid() {
		if legacy != nil && (*legacy != (mode == directory.AgentOutboundModeAutomaticSend)) {
			return "", errStatus(http.StatusBadRequest, "invalid_automation", "outboundMode conflicts with autoReplyEnabled")
		}
		return mode, nil
	}
	if mode != "" {
		return "", errStatus(http.StatusBadRequest, "invalid_automation", "outboundMode must be manual_confirmation or automatic_send")
	}
	if legacy != nil {
		if *legacy {
			return directory.AgentOutboundModeAutomaticSend, nil
		}
		return directory.AgentOutboundModeManualConfirmation, nil
	}
	// Compatibility default for older callers that omitted the former boolean.
	// New callers send the enum explicitly, but omission has always meant the
	// safest manual-confirmation behavior.
	return directory.AgentOutboundModeManualConfirmation, nil
}

func (s *Server) listAgentMailboxes(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if !a.humanAuthenticated || a.spaceID == "" {
		return 0, nil, errStatus(http.StatusForbidden, "space_required", "Agent mailboxes require an authenticated Space")
	}
	mailboxes, err := a.scope.AgentMailboxes(ctx, a.principal.ID, a.spaceID)
	if err != nil {
		return 0, nil, err
	}
	out := make([]agentMailboxInfo, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		out = append(out, toAgentMailboxInfo(mailbox))
	}
	domain := strings.TrimSpace(s.AgentMailboxDomain)
	if domain == "" {
		addresses, err := a.scope.AccountAddresses(ctx, a.acc.ID())
		if err != nil {
			return 0, nil, err
		}
		for _, address := range addresses {
			if separator := strings.LastIndex(address.Address, "@"); separator >= 0 {
				domain = address.Address[separator+1:]
				if address.Primary {
					break
				}
			}
		}
	}
	return http.StatusOK, map[string]any{
		"mailboxes":       out,
		"registeredCount": len(out),
		"maxMailboxes":    s.maxAgentMailboxesPerOwnerSpace(),
		"addressDomain":   domain,
	}, nil
}

func (s *Server) createAgentMailbox(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if !a.humanAuthenticated || a.spaceID == "" {
		return 0, nil, errStatus(http.StatusForbidden, "space_required", "Agent mailbox registration requires an authenticated Space")
	}
	var input createAgentMailboxRequest
	if err := decode(r, &input); err != nil {
		return 0, nil, errStatus(http.StatusBadRequest, "bad_request", "invalid json")
	}
	mailbox, err := a.scope.CreateAgentMailbox(
		ctx, a.principal.ID, a.acc.ID(), a.spaceID, input.Localpart,
		s.AgentMailboxDomain,
		s.maxAgentMailboxesPerOwnerSpace(),
	)
	if errors.Is(err, directory.ErrInvalidLocalpart) {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_localpart", "use lowercase letters, numbers, dots, hyphens, or underscores")
	}
	if errors.Is(err, directory.ErrAddressExists) {
		return 0, nil, errStatus(http.StatusConflict, "address_exists", "mailbox address already exists")
	}
	if errors.Is(err, directory.ErrMailboxNotFound) {
		return 0, nil, errStatus(http.StatusForbidden, "forbidden", "mailbox owner is not available")
	}
	if errors.Is(err, directory.ErrAgentMailboxDomainNotFound) {
		return 0, nil, errStatus(http.StatusConflict, "agent_mailbox_domain_unavailable", "configured Agent mailbox domain is not available for this tenant")
	}
	if errors.Is(err, directory.ErrAgentMailboxLimit) {
		return 0, nil, errStatus(http.StatusConflict, "agent_mailbox_limit_reached", "Agent mailbox limit reached for this Space")
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, toAgentMailboxInfo(mailbox), nil
}

func (s *Server) deleteAgentMailbox(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if !a.humanAuthenticated || a.spaceID == "" {
		return 0, nil, errStatus(http.StatusForbidden, "space_required", "Agent mailbox deletion requires an authenticated Space")
	}
	mailboxID, err := parsePositivePathID(r, "id", "invalid_mailbox")
	if err != nil {
		return 0, nil, err
	}
	if err := a.scope.DeleteAgentMailbox(ctx, a.principal.ID, mailboxID, a.spaceID); err != nil {
		switch {
		case errors.Is(err, directory.ErrMailboxNotFound):
			return 0, nil, errStatus(http.StatusNotFound, "mailbox_not_found", "mailbox was not found in the current Space")
		case errors.Is(err, directory.ErrAgentMailboxNotDeletable):
			return 0, nil, errStatus(http.StatusConflict, "default_mailbox_not_deletable", "the Space default mailbox cannot be deleted")
		default:
			return 0, nil, err
		}
	}
	return http.StatusNoContent, nil, nil
}
