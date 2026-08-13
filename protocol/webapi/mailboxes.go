package webapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

const (
	virtualInboxID   = "inbox"
	virtualStarredID = "starred"
	virtualDraftsID  = "drafts"
	virtualSentID    = "sent"
	virtualArchiveID = "archive"
	virtualTrashID   = "trash"
	virtualJunkID    = "junk"
)

// mailboxInfo is the list-view shape of a mailbox.
type mailboxInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Role   string `json:"role,omitempty"`
	Total  int64  `json:"total"`
	Unread int64  `json:"unread"`
}

func mailboxRole(mb store.Mailbox) string {
	switch {
	case mb.Sent:
		return "sent"
	case mb.Draft:
		return "drafts"
	case mb.Trash:
		return "trash"
	case mb.Junk:
		return "junk"
	case mb.Archive:
		return "archive"
	case strings.EqualFold(mb.Name, "Inbox"):
		return "inbox"
	case strings.EqualFold(mb.Name, "Starred"):
		return "starred"
	case strings.EqualFold(mb.Name, "Drafts"):
		return "drafts"
	case strings.EqualFold(mb.Name, "Sent"):
		return "sent"
	default:
		return ""
	}
}

func includeRequiredMailboxes(mailboxes []mailboxInfo) []mailboxInfo {
	required := []mailboxInfo{
		{ID: virtualInboxID, Name: "Inbox", Role: "inbox"},
		{ID: virtualStarredID, Name: "Starred", Role: "starred"},
		{ID: virtualDraftsID, Name: "Drafts", Role: "drafts"},
		{ID: virtualSentID, Name: "Sent", Role: "sent"},
		{ID: virtualArchiveID, Name: "Archive", Role: "archive"},
		{ID: virtualTrashID, Name: "Trash", Role: "trash"},
		{ID: virtualJunkID, Name: "Junk", Role: "junk"},
	}
	ordered := make([]mailboxInfo, 0, len(mailboxes)+len(required))
	used := make(map[int]bool, len(mailboxes))
	for _, fallback := range required {
		matched := false
		for index, mailbox := range mailboxes {
			if mailbox.Role == fallback.Role || strings.EqualFold(mailbox.Name, fallback.Name) {
				ordered = append(ordered, mailbox)
				used[index] = true
				matched = true
				break
			}
		}
		if !matched {
			ordered = append(ordered, fallback)
		}
	}
	for index, mailbox := range mailboxes {
		if !used[index] {
			ordered = append(ordered, mailbox)
		}
	}
	return ordered
}

func isEmptyRequiredMailbox(name string, mailbox *store.Mailbox) bool {
	if mailbox != nil {
		return false
	}
	return strings.EqualFold(name, "Inbox") ||
		strings.EqualFold(name, "Starred") ||
		strings.EqualFold(name, "Drafts") ||
		strings.EqualFold(name, "Sent") ||
		strings.EqualFold(name, "Archive") ||
		strings.EqualFold(name, "Trash") ||
		strings.EqualFold(name, "Junk")
}

// GET /webapi/v0/mailboxes
func (s *Server) listMailboxes(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	var out []mailboxInfo
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		mbs, e := tx.QueryMailbox().List()
		if e != nil {
			return e
		}
		for _, mb := range mbs {
			out = append(out, mailboxInfo{
				ID:     strconv.FormatInt(mb.ID, 10),
				Name:   mb.Name,
				Role:   mailboxRole(mb),
				Total:  mb.Total,
				Unread: mb.Unread,
			})
		}
		starredTotal, e := tx.QueryMessage().DistinctEmail().FilterKeyword("$flagged", true).Count()
		if e != nil {
			return e
		}
		starredUnread, e := tx.QueryMessage().DistinctEmail().FilterKeyword("$flagged", true).
			FilterFlags(store.Flags{Seen: true}, store.Flags{Seen: false}).Count()
		if e != nil {
			return e
		}
		out = append(out, mailboxInfo{
			ID: virtualStarredID, Name: "Starred", Role: "starred",
			Total: int64(starredTotal), Unread: int64(starredUnread),
		})
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	out = includeRequiredMailboxes(out)
	return http.StatusOK, map[string]any{"mailboxes": out}, nil
}
