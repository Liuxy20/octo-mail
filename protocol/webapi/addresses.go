package webapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
)

type addressInfo struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Primary bool   `json:"primary"`
}

type createAddressRequest struct {
	Localpart string `json:"localpart"`
}

func toAddressInfo(address directory.MailAddress) addressInfo {
	return addressInfo{
		ID:      strconv.FormatInt(address.ID, 10),
		Address: address.Address,
		Primary: address.Primary,
	}
}

func (s *Server) listAddresses(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	addresses, err := a.scope.AccountAddresses(ctx, a.acc.ID())
	if err != nil {
		return 0, nil, err
	}
	out := make([]addressInfo, 0, len(addresses))
	for _, address := range addresses {
		out = append(out, toAddressInfo(address))
	}
	return http.StatusOK, map[string]any{"addresses": out}, nil
}

func (s *Server) createAddress(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if a.agentCredentialID > 0 {
		return 0, nil, errStatus(http.StatusForbidden, "human_owner_required", "mailbox aliases must be managed by the human owner")
	}
	var input createAddressRequest
	if err := decode(r, &input); err != nil {
		return 0, nil, errStatus(http.StatusBadRequest, "bad_request", "invalid json")
	}
	address, err := a.scope.CreateAccountAlias(ctx, a.acc.ID(), input.Localpart)
	if errors.Is(err, directory.ErrInvalidLocalpart) {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_localpart", "use lowercase letters, numbers, dots, hyphens, or underscores")
	}
	if errors.Is(err, directory.ErrAddressExists) {
		return 0, nil, errStatus(http.StatusConflict, "address_exists", "mailbox address already exists")
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, toAddressInfo(address), nil
}

func (s *Server) deleteAddress(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if a.agentCredentialID > 0 {
		return 0, nil, errStatus(http.StatusForbidden, "human_owner_required", "mailbox aliases must be managed by the human owner")
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, nil, errStatus(http.StatusBadRequest, "bad_request", "invalid address id")
	}
	err = a.scope.DeleteAccountAlias(ctx, a.acc.ID(), id)
	if errors.Is(err, directory.ErrAddressNotFound) {
		return 0, nil, errStatus(http.StatusNotFound, "not_found", "mailbox address not found")
	}
	if errors.Is(err, directory.ErrPrimaryAddress) {
		return 0, nil, errStatus(http.StatusBadRequest, "primary_address", "primary mailbox address cannot be deleted")
	}
	if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}
