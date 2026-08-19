package webapi

import (
	"context"
	"net/http"
	"strconv"
)

type accountStateResponse struct {
	State string `json:"state"`
}

// GET /webapi/v0/state returns the authenticated account's current change-log
// head. Clients can poll this lightweight token and reload mailbox projections
// only when it changes.
func (s *Server) getState(ctx context.Context, a authCtx, _ *http.Request) (int, any, error) {
	head, err := a.acc.ChangelogHead(ctx)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, accountStateResponse{State: strconv.FormatInt(int64(head), 10)}, nil
}
