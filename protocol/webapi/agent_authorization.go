package webapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
)

type createAgentDeviceRequest struct {
	BotID          string `json:"botId"`
	BotProfile     string `json:"botProfile,omitempty"`
	ClientName     string `json:"clientName,omitempty"`
	MailboxAddress string `json:"mailboxAddress,omitempty"`
	SpaceID        string `json:"spaceId"`
	CodeChallenge  string `json:"codeChallenge"`
}

type exchangeAgentTokenRequest struct {
	DeviceCode   string `json:"deviceCode"`
	CodeVerifier string `json:"codeVerifier"`
}

type approveAgentAuthorizationRequest struct {
	MailboxID        string                      `json:"mailboxId"`
	OutboundMode     directory.AgentOutboundMode `json:"outboundMode"`
	AutoReplyEnabled *bool                       `json:"autoReplyEnabled,omitempty"`
}

func (s *Server) agentAuthorizationDirectory() (directory.AgentAuthorizationDirectory, error) {
	dir, ok := s.Dir.(directory.AgentAuthorizationDirectory)
	if !ok {
		return nil, errStatus(http.StatusNotImplemented, "agent_auth_unavailable", "Agent Mail authorization is not available")
	}
	return dir, nil
}

func (s *Server) createAgentDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	var input createAgentDeviceRequest
	if err := decode(r, &input); err != nil {
		s.writeErr(w, r, err)
		return
	}
	input.BotID = strings.TrimSpace(input.BotID)
	input.MailboxAddress = strings.TrimSpace(input.MailboxAddress)
	input.SpaceID = strings.TrimSpace(input.SpaceID)
	if input.BotID == "" {
		s.writeErr(w, r, errStatus(http.StatusBadRequest, "invalid_request", "botId is required"))
		return
	}
	if len(input.MailboxAddress) > 320 {
		s.writeErr(w, r, errStatus(http.StatusBadRequest, "invalid_request", "mailboxAddress is too long"))
		return
	}
	if input.SpaceID == "" || len(input.SpaceID) > 200 {
		s.writeErr(w, r, errStatus(http.StatusBadRequest, "invalid_request", "spaceId must contain 1 to 200 characters"))
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(input.CodeChallenge)
	if err != nil || len(challenge) != sha256.Size {
		s.writeErr(w, r, errStatus(http.StatusBadRequest, "invalid_request", "codeChallenge must be a base64url SHA-256 digest"))
		return
	}
	dir, err := s.agentAuthorizationDirectory()
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	device, err := dir.CreateAgentAuthorization(r.Context(), directory.AgentAuthorizationInput{
		BotID: input.BotID, BotProfile: input.BotProfile,
		ClientName: input.ClientName, SpaceID: input.SpaceID, CodeChallenge: input.CodeChallenge,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	verificationURI, verificationComplete := s.agentVerificationURLs(device.UserCode, input.MailboxAddress, input.SpaceID)
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceCode": device.DeviceCode, "userCode": device.UserCode,
		"verificationUri": verificationURI, "verificationUriComplete": verificationComplete,
		"expiresIn": device.ExpiresIn, "interval": device.Interval,
	})
}

func (s *Server) agentVerificationURLs(userCode, mailboxAddress, spaceID string) (string, string) {
	base := strings.TrimSpace(s.AuthorizationURL)
	if base == "" {
		base = "/mail/authorize"
	}
	u, err := url.Parse(base)
	if err != nil {
		return base, base
	}
	q := u.Query()
	q.Set("code", userCode)
	if mailboxAddress != "" {
		q.Set("mailbox", mailboxAddress)
	}
	q.Set("space_id", spaceID)
	u.RawQuery = q.Encode()
	return base, u.String()
}

func (s *Server) exchangeAgentAuthorization(w http.ResponseWriter, r *http.Request) {
	var input exchangeAgentTokenRequest
	if err := decode(r, &input); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !s.allowDeviceTokenPoll(input.DeviceCode) {
		s.writeErr(w, r, errStatus(http.StatusTooManyRequests, "slow_down", "device authorization polling is too frequent"))
		return
	}
	dir, err := s.agentAuthorizationDirectory()
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	credential, err := dir.ExchangeAgentAuthorization(r.Context(), input.DeviceCode, input.CodeVerifier)
	if err != nil {
		s.writeAgentAuthorizationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": credential.AccessToken, "tokenType": "Bearer",
		"mailboxAddress": credential.Address, "botId": credential.BotID,
		"botProfile":       credential.BotProfile,
		"outboundMode":     credential.OutboundMode,
		"autoReplyEnabled": credential.OutboundMode == directory.AgentOutboundModeAutomaticSend,
	})
}

func (s *Server) getAgentAuthorization(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	dir, err := s.agentAuthorizationDirectory()
	if err != nil {
		return 0, nil, err
	}
	authorization, err := dir.AgentAuthorization(ctx, a.principal.ID, a.spaceID, r.PathValue("code"))
	if err != nil {
		return 0, nil, agentAuthorizationStatusError(err)
	}
	mailboxes, err := a.scope.AgentMailboxes(ctx, a.principal.ID, a.spaceID)
	if err != nil {
		return 0, nil, err
	}
	items := make([]agentMailboxInfo, 0, len(mailboxes))
	for _, mailbox := range mailboxes {
		items = append(items, toAgentMailboxInfo(mailbox))
	}
	return http.StatusOK, map[string]any{
		"request": map[string]any{
			"userCode": authorization.UserCode, "botId": authorization.BotID,
			"botProfile": authorization.BotProfile, "clientName": authorization.ClientName,
			"status": authorization.Status, "requestedAt": authorization.RequestedAt,
			"expiresAt":           authorization.ExpiresAt,
			"pollIntervalSeconds": authorization.PollIntervalSeconds,
			"outboundMode":        authorization.OutboundMode,
			"autoReplyEnabled":    authorization.OutboundMode == directory.AgentOutboundModeAutomaticSend,
		},
		"mailboxes": items,
	}, nil
}

func (s *Server) approveAgentAuthorization(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	var input approveAgentAuthorizationRequest
	if err := decode(r, &input); err != nil {
		return 0, nil, err
	}
	mailboxID, err := strconv.ParseInt(input.MailboxID, 10, 64)
	if err != nil || mailboxID <= 0 {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_mailbox", "mailboxId is invalid")
	}
	mode, err := resolveOutboundMode(input.OutboundMode, input.AutoReplyEnabled)
	if err != nil {
		return 0, nil, err
	}
	dir, err := s.agentAuthorizationDirectory()
	if err != nil {
		return 0, nil, err
	}
	if err := dir.ApproveAgentAuthorization(ctx, a.principal.ID, a.spaceID, r.PathValue("code"), mailboxID, mode); err != nil {
		return 0, nil, agentAuthorizationStatusError(err)
	}
	return http.StatusOK, map[string]any{
		"approved":         true,
		"mailboxId":        input.MailboxID,
		"outboundMode":     mode,
		"autoReplyEnabled": mode == directory.AgentOutboundModeAutomaticSend,
	}, nil
}

func (s *Server) revokeAgentMailboxBinding(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	mailboxID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || mailboxID <= 0 {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_mailbox", "mailbox id is invalid")
	}
	if err := s.requireAgentMailboxInSpace(ctx, a, mailboxID); err != nil {
		return 0, nil, err
	}
	dir, err := s.agentAuthorizationDirectory()
	if err != nil {
		return 0, nil, err
	}
	if err := dir.RevokeAgentBinding(ctx, a.principal.ID, mailboxID, a.spaceID); err != nil {
		return 0, nil, agentAuthorizationStatusError(err)
	}
	return http.StatusNoContent, nil, nil
}

func (s *Server) writeAgentAuthorizationError(w http.ResponseWriter, r *http.Request, err error) {
	s.writeErr(w, r, agentAuthorizationStatusError(err))
}

func agentAuthorizationStatusError(err error) error {
	switch {
	case errors.Is(err, directory.ErrAuthorizationPending):
		return errStatus(http.StatusBadRequest, "authorization_pending", "waiting for mailbox authorization")
	case errors.Is(err, directory.ErrAuthorizationExpired):
		return errStatus(http.StatusBadRequest, "authorization_expired", "authorization request expired")
	case errors.Is(err, directory.ErrAuthorizationDenied):
		return errStatus(http.StatusForbidden, "authorization_denied", "authorization request denied")
	case errors.Is(err, directory.ErrAuthorizationUsed):
		return errStatus(http.StatusConflict, "authorization_used", "authorization request was already used")
	case errors.Is(err, directory.ErrInvalidCodeVerifier):
		return errStatus(http.StatusUnauthorized, "invalid_code_verifier", "authorization proof is invalid")
	case errors.Is(err, directory.ErrAuthorizationNotFound):
		return errStatus(http.StatusNotFound, "authorization_not_found", "authorization request was not found")
	case errors.Is(err, directory.ErrAuthorizationSpaceMismatch):
		return errStatus(http.StatusForbidden, "authorization_space_mismatch", "authorization request does not belong to the current Space")
	case errors.Is(err, directory.ErrMailboxNotFound):
		return errStatus(http.StatusForbidden, "mailbox_not_owned", "mailbox is not owned by the current user")
	default:
		return err
	}
}
