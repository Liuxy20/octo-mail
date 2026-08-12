// Package gatewayassert signs and verifies short-lived OCTO identity assertions.
// Assertions are an internal HTTP authentication boundary; they do not replace
// or redefine any SMTP, IMAP, MIME, or JMAP protocol semantics.
package gatewayassert

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	prefix      = "omg_"
	version     = 1
	maxLifetime = 2 * time.Minute
	clockSkew   = 30 * time.Second
)

var ErrInvalid = errors.New("invalid gateway assertion")

// Claims binds one authenticated OCTO actor and Space to one exact upstream
// request. All fields are covered by the HMAC signature.
type Claims struct {
	Version    int    `json:"v"`
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	SpaceID    string `json:"space"`
	MailboxID  string `json:"mailbox,omitempty"`
	Method     string `json:"method"`
	RequestURI string `json:"uri"`
	BodySHA256 string `json:"body_sha256"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	Nonce      string `json:"nonce"`
}

// Sign creates a one-minute assertion for a proxied request.
func Sign(secret []byte, issuer, subject, spaceID, method, requestURI string, body []byte, now time.Time) (string, error) {
	return SignForMailbox(secret, issuer, subject, spaceID, "", method, requestURI, body, now)
}

// SignForMailbox binds an optional selected mailbox to the exact proxied
// request. An empty mailbox selects the owner's default account.
func SignForMailbox(secret []byte, issuer, subject, spaceID, mailboxID, method, requestURI string, body []byte, now time.Time) (string, error) {
	if len(secret) < 32 || strings.TrimSpace(issuer) == "" || strings.TrimSpace(subject) == "" ||
		strings.TrimSpace(spaceID) == "" || strings.TrimSpace(method) == "" || requestURI == "" {
		return "", ErrInvalid
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("gateway assertion nonce: %w", err)
	}
	sum := sha256.Sum256(body)
	claims := Claims{
		Version: version, Issuer: strings.TrimSpace(issuer), Subject: strings.TrimSpace(subject),
		SpaceID: strings.TrimSpace(spaceID), MailboxID: strings.TrimSpace(mailboxID),
		Method:     strings.ToUpper(strings.TrimSpace(method)),
		RequestURI: requestURI, BodySHA256: hex.EncodeToString(sum[:]),
		IssuedAt: now.UTC().Unix(), ExpiresAt: now.UTC().Add(time.Minute).Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal gateway assertion: %w", err)
	}
	payloadText := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payloadText))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return prefix + payloadText + "." + signature, nil
}

// Verify validates the signature, lifetime, actor fields, and exact request
// binding. All failures intentionally collapse to ErrInvalid.
func Verify(secret []byte, token, method, requestURI string, body []byte, now time.Time) (Claims, error) {
	return VerifyForMailbox(secret, token, "", method, requestURI, body, now)
}

// VerifyForMailbox validates the request and requires the signed mailbox
// selector to match the forwarded selector exactly.
func VerifyForMailbox(secret []byte, token, mailboxID, method, requestURI string, body []byte, now time.Time) (Claims, error) {
	if len(secret) < 32 || !strings.HasPrefix(token, prefix) {
		return Claims{}, ErrInvalid
	}
	payloadText, signatureText, ok := strings.Cut(strings.TrimPrefix(token, prefix), ".")
	if !ok || payloadText == "" || signatureText == "" {
		return Claims{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payloadText))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return Claims{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrInvalid
	}
	now = now.UTC()
	issuedAt := time.Unix(claims.IssuedAt, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if claims.Version != version || claims.Issuer == "" || claims.Subject == "" || claims.SpaceID == "" ||
		claims.Nonce == "" || claims.Method != strings.ToUpper(strings.TrimSpace(method)) ||
		claims.MailboxID != strings.TrimSpace(mailboxID) ||
		claims.RequestURI != requestURI || issuedAt.After(now.Add(clockSkew)) || !expiresAt.After(now) ||
		expiresAt.Sub(issuedAt) <= 0 || expiresAt.Sub(issuedAt) > maxLifetime {
		return Claims{}, ErrInvalid
	}
	sum := sha256.Sum256(body)
	wantBody := hex.EncodeToString(sum[:])
	if !hmac.Equal([]byte(claims.BodySHA256), []byte(wantBody)) {
		return Claims{}, ErrInvalid
	}
	return claims, nil
}
