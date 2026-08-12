package webapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/autoreplychain"
)

type autoReplyContextResponse struct {
	Enabled           bool `json:"enabled"`
	AutoReplyCount    int  `json:"autoReplyCount"`
	MaxAutoReplyCount int  `json:"maxAutoReplyCount"`
	NextReplyIsFinal  bool `json:"nextReplyIsFinal"`
	LimitReached      bool `json:"limitReached"`
}

func (s *Server) getAutoReplyContext(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.AutoReplyChain == nil || a.agentCredentialID <= 0 {
		return http.StatusOK, autoReplyContextResponse{}, nil
	}
	dir, ok := s.Dir.(directory.AgentAuthorizationDirectory)
	if !ok {
		return 0, nil, errStatus(http.StatusNotImplemented, "agent_automation_unavailable", "Agent Mail automation is not available")
	}
	enabled, err := dir.AgentAutomationAllowed(ctx, a.agentCredentialID, "mail.message.reply")
	if err != nil {
		return 0, nil, err
	}
	if !enabled {
		return http.StatusOK, autoReplyContextResponse{}, nil
	}
	raw, err := readMessageBytes(ctx, a.acc, r.PathValue("id"))
	if err != nil {
		return 0, nil, err
	}
	chainContext := s.AutoReplyChain.Verify(raw)
	s.logInvalidAutoReplyChain(ctx, a, r.PathValue("id"), chainContext)
	count := 0
	if chainContext.Verification == autoreplychain.VerificationValid {
		count = chainContext.Count
	}
	blocked := s.AutoReplyChain.BlocksAutomaticReply(chainContext)
	if blocked {
		count = s.AutoReplyChain.MaxCount()
		if s.Log != nil {
			s.Log.InfoContext(ctx, "external automated reply stopped before Agent dispatch",
				"account_id", a.acc.ID(), "email_id", r.PathValue("id"))
		}
	}
	return http.StatusOK, autoReplyContextResponse{
		Enabled:           true,
		AutoReplyCount:    count,
		MaxAutoReplyCount: s.AutoReplyChain.MaxCount(),
		NextReplyIsFinal:  !blocked && s.AutoReplyChain.NextReplyIsFinal(chainContext),
		LimitReached:      blocked || s.AutoReplyChain.LimitReached(chainContext),
	}, nil
}

func readMessageBytes(ctx context.Context, acc store.Account, id string) ([]byte, error) {
	var data []byte
	err := acc.ReadTx(ctx, func(tx store.Tx) error {
		messages, err := loadGroup(tx, acc, id)
		if err != nil {
			return err
		}
		reader := acc.MessageReader(ctx, messages[0])
		defer reader.Close()
		data, err = io.ReadAll(reader)
		return err
	})
	return data, err
}

func (s *Server) logInvalidAutoReplyChain(ctx context.Context, a authCtx, emailID string, chainContext autoreplychain.Context) {
	if chainContext.Verification != autoreplychain.VerificationInvalid || s.Log == nil {
		return
	}
	s.Log.WarnContext(ctx, "invalid Agent automatic-reply chain metadata ignored",
		"account_id", a.acc.ID(), "email_id", emailID)
}

func (s *Server) nextAutoReplyMetadata(ctx context.Context, a authCtx, emailID string, sourceRaw []byte, outgoingMessageID string) (autoreplychain.Metadata, error) {
	if s.AutoReplyChain == nil {
		return autoreplychain.Metadata{}, nil
	}
	metadata, chainContext, err := s.AutoReplyChain.Next(sourceRaw, outgoingMessageID)
	s.logInvalidAutoReplyChain(ctx, a, emailID, chainContext)
	if errors.Is(err, autoreplychain.ErrLimitReached) || errors.Is(err, autoreplychain.ErrExternalAutomatedReply) {
		if s.Log != nil {
			s.Log.InfoContext(ctx, "Agent automatic reply stopped by loop protection",
				"account_id", a.acc.ID(), "email_id", emailID,
				"auto_reply_count", chainContext.Count, "max_count", s.AutoReplyChain.MaxCount())
		}
		return autoreplychain.Metadata{}, errStatus(http.StatusConflict, "auto_reply_limit_reached", "automatic reply limit reached; no email was sent")
	}
	if err != nil {
		return autoreplychain.Metadata{}, internalErr("auto_reply_chain_failed", err)
	}
	return metadata, nil
}

func isAgentAutomaticReply(a authCtx, r *http.Request) bool {
	return a.agentCredentialID > 0 && strings.TrimSpace(r.Header.Get(agentAutomationHeader)) == agentAutomationAutoReply
}
