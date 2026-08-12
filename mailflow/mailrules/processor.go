// Package mailrules executes bounded post-storage Agent Mail forwarding rules.
// It cannot influence SMTP acceptance, junk classification, or mailbox routing.
package mailrules

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	moxmessage "github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
)

const (
	defaultMaxForwardMessageSize = 64 << 20
	maxRuleHop                   = 3
	executionFinishTimeout       = 5 * time.Second
)

// Submitter is satisfied by submit.Submitter. Forwarded messages therefore use
// the same durable queue, suppression checks, rate limits, DKIM signing, and
// delivery-result machinery as ordinary outbound mail.
type Submitter interface {
	Submit(ctx context.Context, tenantID, accountID int64, mailFrom string, rcptTo []string, raw []byte) ([]int64, error)
}

// Processor evaluates enabled rules after an Inbox delivery has committed.
type Processor struct {
	Pool           *pgxpool.Pool
	Submitter      Submitter
	RuleMetadata   *rulemetadata.Authenticator
	MaxMessageSize int64
}

func (p *Processor) maxMessageSize() int64 {
	if p.MaxMessageSize > 0 {
		return p.MaxMessageSize
	}
	return defaultMaxForwardMessageSize
}

type rule struct {
	id             int64
	matchFrom      string
	matchSubject   string
	forwardTargets []string
}

type parsedMessage struct {
	from         smtp.Address
	fromName     string
	subject      string
	bodyText     string
	bodyHTML     string
	attachments  []forwardAttachment
	hop          int
	sourceRuleID int64
	automated    bool
}

type forwardAttachment struct {
	filename    string
	contentType string
	content     []byte
}

type targetResult struct {
	Address string `json:"address"`
	Status  string `json:"status"`
	QueueID int64  `json:"queueId,omitempty"`
}

// Process evaluates one committed Inbox Email. sourceEmailID is the stable JMAP
// Email id, not the untrusted RFC Message-ID header. Repeated calls are safe:
// the execution reservation is unique per account, rule, and source Email id.
func (p *Processor) Process(ctx context.Context, accountID, sourceEmailID int64, raw []byte) error {
	if p.Pool == nil || p.Submitter == nil {
		return errors.New("mail rules processor is not configured")
	}
	maxMessageSize := p.maxMessageSize()
	if accountID <= 0 || sourceEmailID <= 0 || len(raw) == 0 || int64(len(raw)) > maxMessageSize {
		return errors.New("invalid mail rule input")
	}
	tenantID, sender, rules, err := p.loadContext(ctx, accountID)
	if err != nil {
		return err
	}
	parsed, err := parseMessageWithLimit(raw, maxMessageSize, p.RuleMetadata, sender, time.Now())
	if err != nil {
		return fmt.Errorf("parse stored message: %w", err)
	}
	var firstErr error
	for _, candidate := range rules {
		if !candidate.matches(parsed) {
			continue
		}
		blockedCode := candidate.blockedCode(parsed)
		status := "matched"
		if blockedCode != "" {
			status = "loop_blocked"
		}
		executionID, reserved, err := p.reserveExecution(ctx, accountID, candidate.id, sourceEmailID, status, parsed.hop, blockedCode)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !reserved || blockedCode != "" {
			continue
		}
		forward, err := composeForwardWithLimit(sender, candidate.forwardTargets, parsed, candidate.id, maxMessageSize, p.RuleMetadata)
		if err != nil {
			_ = p.finishExecution(ctx, accountID, executionID, "failed", nil, "compose_failed")
			if firstErr == nil {
				firstErr = fmt.Errorf("compose rule %d forward: %w", candidate.id, err)
			}
			continue
		}
		queueIDs, err := p.Submitter.Submit(ctx, tenantID, accountID, sender, candidate.forwardTargets, forward)
		if err != nil {
			errorCode := "submit_failed"
			if submit.IsResultUnknown(err) {
				// The queue COMMIT may have succeeded. Keep this execution consumed:
				// reclaiming it could deliver the same forward twice.
				errorCode = "submit_result_unknown"
			}
			finishErr := p.finishFailedExecution(ctx, accountID, executionID, errorCode)
			if firstErr == nil {
				firstErr = fmt.Errorf("submit rule %d forward: %w", candidate.id, err)
				if finishErr != nil {
					firstErr = errors.Join(firstErr, finishErr)
				}
			}
			continue
		}
		results := make([]targetResult, 0, len(candidate.forwardTargets))
		for i, target := range candidate.forwardTargets {
			result := targetResult{Address: target, Status: "queued"}
			if i < len(queueIDs) {
				result.QueueID = queueIDs[i]
			}
			results = append(results, result)
		}
		if err := p.finishExecution(ctx, accountID, executionID, "queued", results, ""); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (p *Processor) finishFailedExecution(ctx context.Context, accountID, executionID int64, errorCode string) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), executionFinishTimeout)
	defer cancel()
	return p.finishExecution(cleanupCtx, accountID, executionID, "failed", nil, errorCode)
}

func (p *Processor) loadContext(ctx context.Context, accountID int64) (int64, string, []rule, error) {
	var tenantID int64
	var sender string
	err := p.Pool.QueryRow(ctx,
		`SELECT acc.tenant_id,addr.localpart || '@' || dom.domain
		 FROM accounts acc
		 JOIN addresses addr ON addr.account_id=acc.id AND addr.tenant_id=acc.tenant_id AND NOT addr.is_alias
		 JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=addr.tenant_id
		 WHERE acc.id=$1 AND NOT acc.disabled`, accountID).Scan(&tenantID, &sender)
	if err != nil {
		return 0, "", nil, fmt.Errorf("resolve rule mailbox: %w", err)
	}
	rows, err := p.Pool.Query(ctx,
		`SELECT id,match_from,match_subject,forward_targets
		 FROM mail_rules WHERE account_id=$1 AND enabled ORDER BY priority DESC,id`, accountID)
	if err != nil {
		return 0, "", nil, fmt.Errorf("load mail rules: %w", err)
	}
	defer rows.Close()
	var rules []rule
	for rows.Next() {
		var candidate rule
		if err := rows.Scan(&candidate.id, &candidate.matchFrom, &candidate.matchSubject, &candidate.forwardTargets); err != nil {
			return 0, "", nil, fmt.Errorf("scan mail rule: %w", err)
		}
		rules = append(rules, candidate)
	}
	if err := rows.Err(); err != nil {
		return 0, "", nil, fmt.Errorf("load mail rules: %w", err)
	}
	return tenantID, sender, rules, nil
}

func (p *Processor) reserveExecution(ctx context.Context, accountID, ruleID, sourceEmailID int64, status string, hop int, errorCode string) (int64, bool, error) {
	var id int64
	err := p.Pool.QueryRow(ctx,
		`INSERT INTO mail_rule_executions
		 (account_id,rule_id,source_email_id,status,hop_count,error_code,completed_at)
		 SELECT $1,$2,$3,$4,$5,$6,CASE WHEN $4='loop_blocked' THEN now() ELSE NULL END
		 FROM mail_rules WHERE account_id=$1 AND id=$2 AND enabled
		 ON CONFLICT (account_id,rule_id,source_email_id) DO UPDATE
		 SET status=EXCLUDED.status,target_results='[]'::jsonb,
		     hop_count=EXCLUDED.hop_count,error_code=EXCLUDED.error_code,
		     completed_at=EXCLUDED.completed_at
		 WHERE EXCLUDED.status='matched'
		   AND mail_rule_executions.status='failed'
		   AND mail_rule_executions.error_code='submit_failed'
		 RETURNING id`, accountID, ruleID, sourceEmailID, status, hop, errorCode).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("reserve mail rule execution: %w", err)
	}
	return id, true, nil
}

func (p *Processor) finishExecution(ctx context.Context, accountID, executionID int64, status string, results []targetResult, errorCode string) error {
	encoded := []byte("[]")
	if results != nil {
		var err error
		encoded, err = json.Marshal(results)
		if err != nil {
			return fmt.Errorf("encode mail rule results: %w", err)
		}
	}
	result, err := p.Pool.Exec(ctx,
		`UPDATE mail_rule_executions
		 SET status=$3,target_results=$4,error_code=$5,completed_at=now()
		 WHERE account_id=$1 AND id=$2`, accountID, executionID, status, encoded, errorCode)
	if err != nil {
		return fmt.Errorf("finish mail rule execution: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("mail rule execution disappeared")
	}
	return nil
}

func parseMessage(raw []byte) (parsedMessage, error) {
	return parseMessageWithLimit(raw, defaultMaxForwardMessageSize, nil, "", time.Time{})
}

func parseMessageWithLimit(raw []byte, maxMessageSize int64, authenticator *rulemetadata.Authenticator, expectedRecipient string, now time.Time) (parsedMessage, error) {
	reader := bytes.NewReader(raw)
	part, err := moxmessage.Parse(nil, false, reader)
	if err != nil {
		return parsedMessage{}, err
	}
	from, envelope, header, err := moxmessage.From(nil, false, reader, &part)
	if err != nil {
		return parsedMessage{}, err
	}
	if err := part.Walk(nil, nil); err != nil {
		return parsedMessage{}, err
	}
	text, html, attachments, err := extractForwardContent(&part, maxMessageSize)
	if err != nil {
		return parsedMessage{}, err
	}
	parsed := parsedMessage{
		from: from, subject: envelope.Subject,
		bodyText: text, bodyHTML: html, attachments: attachments,
	}
	if part.Envelope != nil && len(part.Envelope.From) > 0 {
		parsed.fromName = strings.TrimSpace(part.Envelope.From[0].Name)
	}
	for _, value := range header.Values("Auto-Submitted") {
		value = strings.TrimSpace(value)
		if value != "" && !strings.EqualFold(value, "no") {
			parsed.automated = true
		}
	}
	if authenticator != nil {
		if metadata, ok := authenticator.VerifyHeader(header, expectedRecipient, now); ok {
			parsed.hop = metadata.Hop
			parsed.sourceRuleID = metadata.RuleID
		}
	}
	return parsed, nil
}

func extractForwardContent(root *moxmessage.Part, maxMessageSize int64) (text, html string, attachments []forwardAttachment, err error) {
	var total int64
	var walk func(*moxmessage.Part) error
	walk = func(part *moxmessage.Part) error {
		if len(part.Parts) > 0 {
			for i := range part.Parts {
				if err := walk(&part.Parts[i]); err != nil {
					return err
				}
			}
			return nil
		}
		disposition, filename, _ := part.DispositionFilename()
		mediaType := strings.ToUpper(part.MediaType)
		isText := mediaType == "" || mediaType == "TEXT"
		isAttachment := strings.EqualFold(disposition, "attachment") || filename != "" || !isText
		reader := part.ReaderUTF8OrBinary()
		if reader == nil {
			return nil
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, maxMessageSize+1))
		if readErr != nil {
			return readErr
		}
		if int64(len(content)) > maxMessageSize {
			return errors.New("forwarded MIME part exceeds message size limit")
		}
		if !isAttachment {
			switch strings.ToUpper(part.MediaSubType) {
			case "HTML":
				if html == "" {
					html = string(content)
				}
			default:
				if text == "" {
					text = string(content)
				}
			}
			return nil
		}
		total += int64(len(content))
		if total > maxMessageSize {
			return errors.New("forwarded attachments exceed message size limit")
		}
		if len(attachments) >= 100 {
			return errors.New("forwarded message has too many attachments")
		}
		attachments = append(attachments, forwardAttachment{
			filename: safeForwardFilename(filename), contentType: forwardContentType(part), content: content,
		})
		return nil
	}
	if err := walk(root); err != nil {
		return "", "", nil, err
	}
	return text, html, attachments, nil
}

func safeForwardFilename(filename string) string {
	filename = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, filename)
	filename = filepath.Base(strings.ReplaceAll(filename, "\\", "/"))
	filename = strings.TrimSpace(filename)
	if filename == "" || filename == "." {
		return "attachment"
	}
	return filename
}

func forwardContentType(part *moxmessage.Part) string {
	mediaType := strings.ToLower(part.MediaType)
	subType := strings.ToLower(part.MediaSubType)
	if mediaType == "" || subType == "" {
		return "application/octet-stream"
	}
	return mediaType + "/" + subType
}

func (r rule) matches(message parsedMessage) bool {
	if r.matchFrom != "" {
		configured, err := smtp.ParseAddress(r.matchFrom)
		if err != nil || configured.Localpart.String() != message.from.Localpart.String() ||
			!strings.EqualFold(configured.Domain.ASCII, message.from.Domain.ASCII) {
			return false
		}
	}
	if r.matchSubject != "" && !containsFold(message.subject, r.matchSubject) {
		return false
	}
	return true
}

func containsFold(value, substring string) bool {
	if substring == "" {
		return true
	}
	valueRunes := []rune(value)
	substringRunes := []rune(substring)
	if len(substringRunes) > len(valueRunes) {
		return false
	}
	for start := 0; start+len(substringRunes) <= len(valueRunes); start++ {
		if strings.EqualFold(string(valueRunes[start:start+len(substringRunes)]), substring) {
			return true
		}
	}
	return false
}

func (r rule) blockedCode(message parsedMessage) string {
	if message.automated {
		return "auto_submitted"
	}
	if message.hop >= maxRuleHop {
		return "hop_limit"
	}
	if message.sourceRuleID == r.id {
		return "rule_repeated"
	}
	return ""
}

func composeForward(from string, targets []string, source parsedMessage, ruleID int64, authenticator *rulemetadata.Authenticator) (raw []byte, err error) {
	return composeForwardWithLimit(from, targets, source, ruleID, defaultMaxForwardMessageSize, authenticator)
}

func composeForwardWithLimit(from string, targets []string, source parsedMessage, ruleID, maxMessageSize int64, authenticator *rulemetadata.Authenticator) (raw []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("compose panic: %v", recovered)
			raw = nil
		}
	}()
	fromAddress, err := smtp.ParseAddress(from)
	if err != nil {
		return nil, err
	}
	to := make([]moxmessage.NameAddress, 0, len(targets))
	for _, target := range targets {
		address, parseErr := smtp.ParseAddress(target)
		if parseErr != nil {
			return nil, parseErr
		}
		to = append(to, moxmessage.NameAddress{Address: address})
	}
	var buf bytes.Buffer
	composer := moxmessage.NewComposer(&buf, maxMessageSize, false)
	multipartWriter := multipart.NewWriter(composer)
	displayName := source.fromName
	if displayName == "" {
		displayName = source.from.String()
	}
	displayName += " via Agent Mail"
	composer.HeaderAddrs("From", []moxmessage.NameAddress{{DisplayName: displayName, Address: fromAddress}})
	composer.HeaderAddrs("To", to)
	subject := strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "").Replace(source.subject))
	composer.Subject(subject)
	composer.Header("Date", time.Now().Format(time.RFC1123Z))
	messageID, err := newMessageID(fromAddress.Domain.ASCII)
	if err != nil {
		return nil, err
	}
	composer.Header("Message-ID", messageID)
	composer.Header("Auto-Submitted", "auto-generated")
	if authenticator != nil {
		metadata := rulemetadata.Metadata{
			OriginalFrom: source.from.String(),
			SentBy:       fromAddress.String(),
			RuleID:       ruleID,
			Hop:          source.hop + 1,
			MessageID:    messageID,
			Recipients:   targets,
			ExpiresAt:    rulemetadata.Expiry(time.Now()),
		}
		signature, err := authenticator.Sign(metadata)
		if err != nil {
			return nil, fmt.Errorf("sign rule metadata: %w", err)
		}
		composer.Header(rulemetadata.HeaderOriginalFrom, metadata.OriginalFrom)
		composer.Header(rulemetadata.HeaderSentBy, metadata.SentBy)
		composer.Header(rulemetadata.HeaderRuleID, strconv.FormatInt(metadata.RuleID, 10))
		composer.Header(rulemetadata.HeaderRuleHop, strconv.Itoa(metadata.Hop))
		recipients, err := rulemetadata.CanonicalRecipients(metadata.Recipients)
		if err != nil {
			return nil, fmt.Errorf("canonicalize rule metadata recipients: %w", err)
		}
		composer.Header(rulemetadata.HeaderRecipients, recipients)
		composer.Header(rulemetadata.HeaderExpires, strconv.FormatInt(metadata.ExpiresAt, 10))
		composer.Header(rulemetadata.HeaderSignature, signature)
	}
	composer.Header("MIME-Version", "1.0")
	composer.Header("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": multipartWriter.Boundary()}))
	composer.Line()
	if err := writeForwardBody(multipartWriter, source); err != nil {
		return nil, err
	}
	for _, attachment := range source.attachments {
		if err := writeForwardAttachment(multipartWriter, attachment); err != nil {
			return nil, err
		}
	}
	if err := multipartWriter.Close(); err != nil {
		return nil, err
	}
	composer.Flush()
	return buf.Bytes(), nil
}

func writeForwardBody(multipartWriter *multipart.Writer, source parsedMessage) error {
	if source.bodyHTML == "" {
		part, err := multipartWriter.CreatePart(textproto.MIMEHeader{
			"Content-Type": {"text/plain; charset=utf-8"},
		})
		if err != nil {
			return err
		}
		_, err = io.WriteString(part, source.bodyText)
		return err
	}
	if source.bodyText == "" {
		part, err := multipartWriter.CreatePart(textproto.MIMEHeader{
			"Content-Type": {"text/html; charset=utf-8"},
		})
		if err != nil {
			return err
		}
		_, err = io.WriteString(part, source.bodyHTML)
		return err
	}

	var alternative bytes.Buffer
	alternativeWriter := multipart.NewWriter(&alternative)
	textPart, err := alternativeWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/plain; charset=utf-8"},
	})
	if err != nil {
		return err
	}
	if _, err := io.WriteString(textPart, source.bodyText); err != nil {
		return err
	}
	htmlPart, err := alternativeWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/html; charset=utf-8"},
	})
	if err != nil {
		return err
	}
	if _, err := io.WriteString(htmlPart, source.bodyHTML); err != nil {
		return err
	}
	if err := alternativeWriter.Close(); err != nil {
		return err
	}
	part, err := multipartWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type": {mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": alternativeWriter.Boundary()})},
	})
	if err != nil {
		return err
	}
	_, err = part.Write(alternative.Bytes())
	return err
}

func writeForwardAttachment(multipartWriter *multipart.Writer, attachment forwardAttachment) error {
	part, err := multipartWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {mime.FormatMediaType(attachment.contentType, map[string]string{"name": attachment.filename})},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {mime.FormatMediaType("attachment", map[string]string{"filename": attachment.filename})},
	})
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(attachment.content)
	for start := 0; start < len(encoded); start += 76 {
		end := start + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		if _, err := io.WriteString(part, encoded[start:end]+"\r\n"); err != nil {
			return err
		}
	}
	return nil
}

func newMessageID(domain string) (string, error) {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	if domain == "" {
		domain = "localhost"
	}
	return "<" + base64.RawURLEncoding.EncodeToString(random) + "@" + domain + ">", nil
}
