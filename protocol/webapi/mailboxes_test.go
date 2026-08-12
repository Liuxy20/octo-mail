package webapi

import (
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

func TestIncludeRequiredMailboxesAddsEmptySystemFolders(t *testing.T) {
	mailboxes := includeRequiredMailboxes(nil)
	if len(mailboxes) != 7 {
		t.Fatalf("mailboxes = %d, want all seven system folders", len(mailboxes))
	}
	want := []mailboxInfo{
		{ID: virtualInboxID, Name: "Inbox", Role: "inbox"},
		{ID: virtualStarredID, Name: "Starred", Role: "starred"},
		{ID: virtualDraftsID, Name: "Drafts", Role: "drafts"},
		{ID: virtualSentID, Name: "Sent", Role: "sent"},
		{ID: virtualArchiveID, Name: "Archive", Role: "archive"},
		{ID: virtualTrashID, Name: "Trash", Role: "trash"},
		{ID: virtualJunkID, Name: "Junk", Role: "junk"},
	}
	for index := range want {
		if mailboxes[index].ID != want[index].ID || mailboxes[index].Role != want[index].Role {
			t.Fatalf("mailbox %d = %#v, want %#v", index, mailboxes[index], want[index])
		}
	}
}

func TestIncludeRequiredMailboxesKeepsPersistedFoldersAndOthers(t *testing.T) {
	mailboxes := includeRequiredMailboxes([]mailboxInfo{
		{ID: "42", Name: "Inbox", Role: "inbox", Total: 2},
		{ID: "43", Name: "Sent", Role: "sent", Total: 1},
		{ID: "44", Name: "Archive", Role: "archive"},
	})
	if len(mailboxes) != 7 {
		t.Fatalf("mailboxes = %#v, want seven system folders", mailboxes)
	}
	if mailboxes[0].ID != "42" || mailboxes[1].ID != virtualStarredID || mailboxes[2].ID != virtualDraftsID || mailboxes[3].ID != "43" || mailboxes[4].ID != "44" || mailboxes[5].ID != virtualTrashID || mailboxes[6].ID != virtualJunkID {
		t.Fatalf("mailboxes = %#v, persisted folders or ordering lost", mailboxes)
	}
}

func TestIsEmptyRequiredMailbox(t *testing.T) {
	for _, name := range []string{"Inbox", "Starred", "Drafts", "Sent", "Archive", "Trash", "Junk"} {
		if !isEmptyRequiredMailbox(name, nil) {
			t.Fatalf("missing %s should be treated as an empty virtual mailbox", name)
		}
	}
	if isEmptyRequiredMailbox("Other", nil) {
		t.Fatal("an arbitrary missing mailbox must still return not found")
	}
	if isEmptyRequiredMailbox("Drafts", &store.Mailbox{Name: "Drafts"}) {
		t.Fatal("a persisted Drafts mailbox must use the regular query path")
	}
}
