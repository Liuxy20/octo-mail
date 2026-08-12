package webapi

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	moxmessage "github.com/mjl-/mox/message"
)

const (
	maxAttachmentMetadata = 100
)

type receivedAttachment struct {
	PartID      string `json:"partId"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Disposition string `json:"disposition,omitempty"`
	Size        int64  `json:"size"`
}

func parseAttachments(data []byte) ([]receivedAttachment, bool) {
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(data), int64(len(data)))
	if err != nil && len(part.Parts) == 0 {
		return []receivedAttachment{}, false
	}
	return collectAttachments(&part)
}

func collectAttachments(root *moxmessage.Part) ([]receivedAttachment, bool) {
	out := make([]receivedAttachment, 0)
	truncated := false
	var walk func(*moxmessage.Part, string)
	walk = func(part *moxmessage.Part, partID string) {
		if truncated {
			return
		}
		if len(part.Parts) > 0 {
			for i := range part.Parts {
				walk(&part.Parts[i], partID+"."+strconv.Itoa(i+1))
			}
			return
		}
		disposition, filename, _ := part.DispositionFilename()
		if !isAttachmentPart(part, disposition, filename) {
			return
		}
		if len(out) == maxAttachmentMetadata {
			truncated = true
			return
		}
		out = append(out, receivedAttachment{
			PartID:      partID,
			Filename:    safeAttachmentFilename(filename),
			ContentType: attachmentContentType(part),
			Disposition: strings.ToLower(disposition),
			Size:        part.DecodedSize,
		})
	}
	walk(root, "1")
	return out, truncated
}

func isAttachmentPart(part *moxmessage.Part, disposition, filename string) bool {
	if strings.EqualFold(disposition, "attachment") || filename != "" {
		return true
	}
	mediaType := strings.ToUpper(part.MediaType)
	return mediaType != "" && mediaType != "TEXT" && mediaType != "MULTIPART"
}

func attachmentContentType(part *moxmessage.Part) string {
	mediaType := strings.ToLower(part.MediaType)
	subType := strings.ToLower(part.MediaSubType)
	if mediaType == "" || subType == "" {
		return "application/octet-stream"
	}
	return mediaType + "/" + subType
}

func attachmentDownloadSizeAllowed(size, maxSize int64) bool {
	return maxSize > 0 && size >= 0 && size <= maxSize
}

func safeAttachmentFilename(filename string) string {
	filename = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, filename)
	filename = filepath.Base(strings.ReplaceAll(filename, "\\", "/"))
	filename = strings.TrimSpace(filename)
	if filename == "" || filename == "." {
		filename = "attachment"
	}
	if runes := []rune(filename); len(runes) > 255 {
		filename = string(runes[:255])
	}
	return filename
}

func validPartID(partID string) bool {
	if partID == "" || len(partID) > 128 {
		return false
	}
	for _, segment := range strings.Split(partID, ".") {
		value, err := strconv.Atoi(segment)
		if err != nil || value <= 0 {
			return false
		}
	}
	return true
}

func findMIMEPart(root *moxmessage.Part, partID string) *moxmessage.Part {
	if !validPartID(partID) {
		return nil
	}
	segments := strings.Split(partID, ".")
	if segments[0] != "1" {
		return nil
	}
	part := root
	for _, segment := range segments[1:] {
		index, _ := strconv.Atoi(segment)
		if index > len(part.Parts) {
			return nil
		}
		part = &part.Parts[index-1]
	}
	return part
}

func (s *Server) downloadAttachment(w http.ResponseWriter, r *http.Request) {
	a, err := s.auth(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	partID := r.PathValue("partId")
	if !validPartID(partID) {
		s.writeErr(w, r, errStatus(http.StatusBadRequest, "invalid_part_id", "invalid MIME part id"))
		return
	}

	var message store.Message
	err = a.acc.ReadTx(r.Context(), func(tx store.Tx) error {
		messages, err := loadGroup(tx, a.acc, r.PathValue("id"))
		if err != nil {
			return err
		}
		message = messages[0]
		return nil
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}

	reader := a.acc.MessageReader(r.Context(), message)
	defer reader.Close()
	maxMessageSize := s.maxMessageSize()
	if message.Size > maxMessageSize {
		s.writeErr(w, r, errStatus(http.StatusRequestEntityTooLarge, "message_too_large", "message exceeds the attachment parsing limit"))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxMessageSize+1))
	if err != nil {
		s.writeErr(w, r, internalErr("attachment_read_failed", err))
		return
	}
	if int64(len(raw)) > maxMessageSize {
		s.writeErr(w, r, errStatus(http.StatusRequestEntityTooLarge, "message_too_large", "message exceeds the attachment parsing limit"))
		return
	}
	root, parseErr := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if parseErr != nil && len(root.Parts) == 0 {
		s.writeErr(w, r, errStatus(http.StatusUnprocessableEntity, "invalid_mime", "message MIME structure cannot be parsed"))
		return
	}
	part := findMIMEPart(&root, partID)
	if part == nil || len(part.Parts) > 0 {
		s.writeErr(w, r, errStatus(http.StatusNotFound, "not_found", "no such attachment"))
		return
	}
	disposition, filename, _ := part.DispositionFilename()
	if !isAttachmentPart(part, disposition, filename) {
		s.writeErr(w, r, errStatus(http.StatusNotFound, "not_found", "no such attachment"))
		return
	}
	if !attachmentDownloadSizeAllowed(part.DecodedSize, maxMessageSize) {
		s.writeErr(w, r, errStatus(http.StatusRequestEntityTooLarge, "attachment_too_large", "attachment exceeds the download limit"))
		return
	}
	content := part.Reader()
	if content == nil {
		s.writeErr(w, r, errStatus(http.StatusUnprocessableEntity, "invalid_mime", "attachment content cannot be decoded"))
		return
	}

	filename = safeAttachmentFilename(filename)
	w.Header().Set("Content-Type", attachmentContentType(part))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// DecodedSize is MIME-parser metadata and can disagree with a malformed or
	// truncated transfer-encoded stream. Let net/http use chunked delivery rather
	// than promising clients an unverified byte count.
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, io.LimitReader(content, maxMessageSize+1))
}
