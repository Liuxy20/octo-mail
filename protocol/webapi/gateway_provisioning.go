package webapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
)

const maxGatewayProvisioningBodySize = 4 << 10

type gatewayProvisioningRequest struct {
	Localpart string `json:"localpart"`
}

func (s *Server) ensureGatewayIdentity(w http.ResponseWriter, r *http.Request) {
	if len(s.GatewaySecret) < 32 {
		s.writeErr(w, r, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxGatewayProvisioningBodySize)
	body, err := readAndRestoreAuthBody(r, maxGatewayProvisioningBodySize)
	if err != nil {
		s.writeErr(w, r, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed"))
		return
	}
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer omg_") || strings.TrimSpace(r.Header.Get("X-Octo-Mailbox-ID")) != "" {
		s.writeErr(w, r, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed"))
		return
	}
	verificationTime := time.Now().UTC()
	claims, err := gatewayassert.Verify(
		s.GatewaySecret, strings.TrimPrefix(authorization, "Bearer "),
		r.Method, r.URL.RequestURI(), body, verificationTime,
	)
	if err != nil {
		s.writeErr(w, r, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed"))
		return
	}
	replayDir, ok := s.Dir.(directory.GatewayAssertionReplayDirectory)
	if !ok || replayDir.ConsumeGatewayAssertionNonce(
		r.Context(), claims.Issuer, claims.Nonce,
		time.Unix(claims.ExpiresAt, 0), verificationTime,
	) != nil {
		s.writeErr(w, r, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed"))
		return
	}

	var input gatewayProvisioningRequest
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := decodeStrict(r, &input); err != nil {
		s.writeErr(w, r, err)
		return
	}
	provisioner, ok := s.Dir.(directory.GatewayProvisioningDirectory)
	if !ok {
		s.writeErr(w, r, internalErr("gateway_provisioning_unavailable", errors.New("directory does not support gateway provisioning")))
		return
	}
	result, err := provisioner.EnsureGatewayIdentity(r.Context(), directory.GatewayProvisioningInput{
		Issuer: claims.Issuer, Subject: claims.Subject, SpaceID: claims.SpaceID,
		Localpart: input.Localpart, Domain: s.AgentMailboxDomain,
	})
	if err != nil {
		switch {
		case errors.Is(err, directory.ErrInvalidLocalpart):
			s.writeErr(w, r, errStatus(http.StatusBadRequest, "invalid_localpart", "use lowercase letters, numbers, dots, hyphens, or underscores"))
		case errors.Is(err, directory.ErrAgentMailboxDomainNotFound):
			s.writeErr(w, r, errStatus(http.StatusConflict, "agent_mailbox_domain_unavailable", "configured Agent mailbox domain is not available"))
		case errors.Is(err, directory.ErrGatewayIdentityDisabled):
			s.writeErr(w, r, errStatus(http.StatusForbidden, "gateway_identity_disabled", "gateway identity is disabled"))
		case errors.Is(err, directory.ErrGatewayProvisioningConflict):
			s.writeErr(w, r, errStatus(http.StatusConflict, "gateway_provisioning_conflict", "gateway identity could not be provisioned"))
		default:
			s.writeErr(w, r, internalErr("gateway_provisioning_failed", err))
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenantId": result.TenantID, "ownerPrincipalId": result.PrincipalID,
		"defaultAccountId": result.DefaultAccountID, "address": result.Address,
		"created": result.Created,
	})
}
