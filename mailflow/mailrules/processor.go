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

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/text/cases"

	moxmessage "github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
)

const (
	defaultMaxForwardMessageSize = 64 << 20
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
	matchMode      string
	conditions     []directory.MailRuleCondition
	matchFrom      string
	matchSubject   string
	forwardTargets []string
}

type parsedMessage struct {
	from             smtp.Address
	fromName         string
	recipients       []string
	subject          string
	bodyText         string
	bodyHTML         string
	foldedFrom       string
	foldedRecipients []string
	foldedSubject    string
	foldedBodyText   string
	foldedBodyHTML   string
	matchValuesReady bool
	attachments      []forwardAttachment
	hop              int
	ruleTrace        []int64
	originalFrom     string
	trustedMessageID string
	trustedRule      bool
	automated        bool
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
	tenantID, sender, accountAddresses, rules, err := p.loadContext(ctx, accountID)
	if err != nil {
		return err
	}
	parsed, err := parseMessageWithLimit(raw, maxMessageSize, p.RuleMetadata, accountAddresses, time.Now())
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
		executionID, reserved, err := p.reserveExecution(ctx, accountID, candidate.id, sourceEmailID, parsed.trustedMessageID, status, parsed.hop, blockedCode)
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

func (p *Processor) loadContext(ctx context.Context, accountID int64) (int64, string, []string, []rule, error) {
	var tenantID int64
	var sender string
	err := p.Pool.QueryRow(ctx,
		`SELECT acc.tenant_id,addr.localpart || '@' || dom.domain
		 FROM accounts acc
		 JOIN addresses addr ON addr.account_id=acc.id AND addr.tenant_id=acc.tenant_id AND NOT addr.is_alias
		 JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=addr.tenant_id
		 WHERE acc.id=$1 AND NOT acc.disabled`, accountID).Scan(&tenantID, &sender)
	if err != nil {
		return 0, "", nil, nil, fmt.Errorf("resolve rule mailbox: %w", err)
	}
	addressRows, err := p.Pool.Query(ctx,
		`SELECT addr.localpart || '@' || dom.domain
		 FROM addresses addr
		 JOIN accounts acc ON acc.id=addr.account_id AND acc.tenant_id=addr.tenant_id
		 JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=addr.tenant_id
		 WHERE acc.id=$1 AND NOT acc.disabled ORDER BY addr.id`, accountID)
	if err != nil {
		return 0, "", nil, nil, fmt.Errorf("load rule mailbox addresses: %w", err)
	}
	var accountAddresses []string
	for addressRows.Next() {
		var address string
		if err := addressRows.Scan(&address); err != nil {
			addressRows.Close()
			return 0, "", nil, nil, fmt.Errorf("scan rule mailbox address: %w", err)
		}
		accountAddresses = append(accountAddresses, address)
	}
	if err := addressRows.Err(); err != nil {
		addressRows.Close()
		return 0, "", nil, nil, fmt.Errorf("load rule mailbox addresses: %w", err)
	}
	addressRows.Close()
	rows, err := p.Pool.Query(ctx,
		`SELECT id,match_mode,conditions,match_from,match_subject,forward_targets
		 FROM mail_rules WHERE account_id=$1 AND enabled ORDER BY priority DESC,id`, accountID)
	if err != nil {
		return 0, "", nil, nil, fmt.Errorf("load mail rules: %w", err)
	}
	defer rows.Close()
	var rules []rule
	for rows.Next() {
		var candidate rule
		var conditions []byte
		if err := rows.Scan(&candidate.id, &candidate.matchMode, &conditions, &candidate.matchFrom, &candidate.matchSubject, &candidate.forwardTargets); err != nil {
			return 0, "", nil, nil, fmt.Errorf("scan mail rule: %w", err)
		}
		if err := json.Unmarshal(conditions, &candidate.conditions); err != nil {
			return 0, "", nil, nil, fmt.Errorf("decode mail rule conditions: %w", err)
		}
		if len(candidate.conditions) == 0 {
			if candidate.matchFrom != "" {
				candidate.conditions = append(candidate.conditions, directory.MailRuleCondition{Field: "from", Operator: "equals", Value: candidate.matchFrom})
			}
			if candidate.matchSubject != "" {
				candidate.conditions = append(candidate.conditions, directory.MailRuleCondition{Field: "subject", Operator: "contains", Value: candidate.matchSubject})
			}
		}
		rules = append(rules, candidate)
	}
	if err := rows.Err(); err != nil {
		return 0, "", nil, nil, fmt.Errorf("load mail rules: %w", err)
	}
	return tenantID, sender, accountAddresses, rules, nil
}

func (p *Processor) reserveExecution(ctx context.Context, accountID, ruleID, sourceEmailID int64, sourceMessageID, status string, hop int, errorCode string) (int64, bool, error) {
	var id int64
	err := p.Pool.QueryRow(ctx,
		`INSERT INTO mail_rule_executions
		 (account_id,rule_id,source_email_id,source_message_id,status,hop_count,error_code,completed_at)
		 SELECT $1,$2,$3,$4,$5,$6,$7,CASE WHEN $5='loop_blocked' THEN now() ELSE NULL END
		 FROM mail_rules WHERE account_id=$1 AND id=$2 AND enabled
		 ON CONFLICT (account_id,rule_id,source_email_id) DO UPDATE
		 SET status=EXCLUDED.status,target_results='[]'::jsonb,
		     hop_count=EXCLUDED.hop_count,error_code=EXCLUDED.error_code,
		     completed_at=EXCLUDED.completed_at
		 WHERE EXCLUDED.status='matched'
		   AND mail_rule_executions.status='failed'
		   AND mail_rule_executions.error_code='submit_failed'
		 RETURNING id`, accountID, ruleID, sourceEmailID, sourceMessageID, status, hop, errorCode).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	var pgErr *pgconn.PgError
	if sourceMessageID != "" && errors.As(err, &pgErr) && pgErr.Code == "23505" && isTrustedMessageReplayConstraint(pgErr.ConstraintName) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("reserve mail rule execution: %w", err)
	}
	return id, true, nil
}

func isTrustedMessageReplayConstraint(name string) bool {
	if name == "mail_rule_executions_trusted_message_once" {
		return true
	}
	// PostgreSQL creates one inherited index per hash partition and truncates
	// its generated name to 63 bytes.
	return strings.HasPrefix(name, "mail_rule_executions_p") &&
		strings.HasSuffix(name, "_account_id_rule_id_source_message_i_idx")
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
	return parseMessageWithLimit(raw, defaultMaxForwardMessageSize, nil, nil, time.Time{})
}

func parseMessageWithLimit(raw []byte, maxMessageSize int64, authenticator *rulemetadata.Authenticator, expectedRecipients []string, now time.Time) (parsedMessage, error) {
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
	if part.Envelope != nil {
		if len(part.Envelope.From) > 0 {
			parsed.fromName = strings.TrimSpace(part.Envelope.From[0].Name)
		}
		parsed.recipients = appendEnvelopeAddresses(parsed.recipients, part.Envelope.To)
		parsed.recipients = appendEnvelopeAddresses(parsed.recipients, part.Envelope.CC)
		parsed.recipients = appendEnvelopeAddresses(parsed.recipients, part.Envelope.BCC)
	}
	for _, value := range header.Values("Auto-Submitted") {
		value = strings.TrimSpace(value)
		if value != "" && !strings.EqualFold(value, "no") {
			parsed.automated = true
		}
	}
	if authenticator != nil {
		if metadata, ok := authenticator.VerifyAny(raw, expectedRecipients, now); ok && metadata.ChainTrusted {
			parsed.hop = metadata.Hop
			parsed.ruleTrace = append([]int64(nil), metadata.RuleTrace...)
			parsed.originalFrom = metadata.OriginalFrom
			parsed.trustedMessageID = metadata.MessageID
			parsed.trustedRule = true
		}
	}
	parsed.prepareMatchValues()
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
	message.prepareMatchValues()
	conditions := r.conditions
	if len(conditions) == 0 {
		if r.matchFrom != "" {
			conditions = append(conditions, directory.MailRuleCondition{Field: "from", Operator: "equals", Value: r.matchFrom})
		}
		if r.matchSubject != "" {
			conditions = append(conditions, directory.MailRuleCondition{Field: "subject", Operator: "contains", Value: r.matchSubject})
		}
	}
	if len(conditions) == 0 {
		return false
	}
	matched := r.matchMode != "any"
	for _, condition := range conditions {
		conditionMatched := mailRuleConditionMatchesPrepared(condition, message)
		if r.matchMode == "any" && conditionMatched {
			return true
		}
		if r.matchMode != "any" && !conditionMatched {
			return false
		}
	}
	return matched
}

func mailRuleConditionMatches(condition directory.MailRuleCondition, message parsedMessage) bool {
	message.prepareMatchValues()
	return mailRuleConditionMatchesPrepared(condition, message)
}

func mailRuleConditionMatchesPrepared(condition directory.MailRuleCondition, message parsedMessage) bool {
	switch condition.Operator {
	case "contains", "not_contains", "equals":
	default:
		return false
	}
	var values, foldedValues []string
	switch condition.Field {
	case "from":
		values = []string{message.from.String()}
		foldedValues = []string{message.foldedFrom}
	case "to":
		values = message.recipients
		foldedValues = message.foldedRecipients
	case "subject":
		values = []string{message.subject}
		foldedValues = []string{message.foldedSubject}
	case "body":
		values = []string{message.bodyText, message.bodyHTML}
		foldedValues = []string{message.foldedBodyText, message.foldedBodyHTML}
	case "subject_or_body":
		values = []string{message.subject, message.bodyText, message.bodyHTML}
		foldedValues = []string{message.foldedSubject, message.foldedBodyText, message.foldedBodyHTML}
	default:
		return false
	}
	contains := false
	foldedNeedle := cases.Fold().String(condition.Value)
	for _, value := range foldedValues {
		if strings.Contains(value, foldedNeedle) {
			contains = true
			break
		}
	}
	switch condition.Operator {
	case "not_contains":
		return len(values) > 0 && !contains
	case "contains":
		return contains
	case "equals":
		if condition.Field == "from" {
			configured, err := smtp.ParseAddress(condition.Value)
			return err == nil && configured.Localpart.String() == message.from.Localpart.String() &&
				strings.EqualFold(configured.Domain.ASCII, message.from.Domain.ASCII)
		}
		return slicesEqualFold(values, condition.Value)
	}
	return false
}

func slicesEqualFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}

func appendEnvelopeAddresses(values []string, addresses []moxmessage.Address) []string {
	for _, address := range addresses {
		mailbox := strings.TrimSpace(address.User)
		if address.Host != "" {
			mailbox += "@" + address.Host
		}
		if mailbox != "" {
			values = append(values, mailbox)
		}
	}
	return values
}

func (m *parsedMessage) prepareMatchValues() {
	if m.matchValuesReady {
		return
	}
	folder := cases.Fold()
	m.foldedFrom = folder.String(m.from.String())
	m.foldedRecipients = make([]string, len(m.recipients))
	for i, recipient := range m.recipients {
		m.foldedRecipients[i] = folder.String(recipient)
	}
	m.foldedSubject = folder.String(m.subject)
	m.foldedBodyText = folder.String(m.bodyText)
	m.foldedBodyHTML = folder.String(m.bodyHTML)
	m.matchValuesReady = true
}

func (r rule) blockedCode(message parsedMessage) string {
	if message.automated && !message.trustedRule {
		return "auto_submitted"
	}
	for _, ruleID := range message.ruleTrace {
		if ruleID == r.id {
			return "rule_repeated"
		}
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
	var metadata *rulemetadata.Metadata
	if authenticator != nil {
		ruleTrace := append(append([]int64(nil), source.ruleTrace...), ruleID)
		originalFrom := source.from.String()
		if source.trustedRule && source.originalFrom != "" {
			originalFrom = source.originalFrom
		}
		value := rulemetadata.Metadata{
			OriginalFrom: originalFrom,
			SentBy:       fromAddress.String(),
			RuleID:       ruleID,
			Hop:          len(ruleTrace),
			RuleTrace:    ruleTrace,
			MessageID:    messageID,
			Recipients:   targets,
			ExpiresAt:    rulemetadata.Expiry(time.Now()),
		}
		metadata = &value
		composer.Header(rulemetadata.HeaderOriginalFrom, value.OriginalFrom)
		composer.Header(rulemetadata.HeaderSentBy, value.SentBy)
		composer.Header(rulemetadata.HeaderRuleID, strconv.FormatInt(value.RuleID, 10))
		composer.Header(rulemetadata.HeaderRuleHop, strconv.Itoa(value.Hop))
		trace, err := rulemetadata.FormatRuleTrace(value.RuleTrace)
		if err != nil {
			return nil, fmt.Errorf("format rule trace: %w", err)
		}
		composer.Header(rulemetadata.HeaderRuleTrace, trace)
		recipients, err := rulemetadata.CanonicalRecipients(value.Recipients)
		if err != nil {
			return nil, fmt.Errorf("canonicalize rule metadata recipients: %w", err)
		}
		composer.Header(rulemetadata.HeaderRecipients, recipients)
		composer.Header(rulemetadata.HeaderExpires, strconv.FormatInt(value.ExpiresAt, 10))
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
	raw = buf.Bytes()
	if metadata != nil {
		signature, err := authenticator.Sign(*metadata, raw)
		if err != nil {
			return nil, fmt.Errorf("sign rule metadata: %w", err)
		}
		raw, err = insertMessageHeader(raw, rulemetadata.HeaderSignature, signature)
		if err != nil {
			return nil, err
		}
		if maxMessageSize > 0 && int64(len(raw)) > maxMessageSize {
			return nil, errors.New("forwarded message exceeds message size limit")
		}
	}
	return raw, nil
}

func insertMessageHeader(raw []byte, name, value string) ([]byte, error) {
	separator := bytes.Index(raw, []byte("\r\n\r\n"))
	if separator < 0 {
		return nil, errors.New("composed message has no header boundary")
	}
	line := []byte(name + ": " + value + "\r\n")
	result := make([]byte, 0, len(raw)+len(line))
	result = append(result, raw[:separator+2]...)
	result = append(result, line...)
	result = append(result, raw[separator+2:]...)
	return result, nil
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
