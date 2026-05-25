package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// maxWebhookBodyBytes caps the size of a Discourse webhook payload.
// Stock Discourse user events are <10 KiB; this leaves margin without
// letting a hostile sender exhaust memory before signature verification.
const maxWebhookBodyBytes = 64 * 1024

// webhookEndpoint accepts Discourse webhook deliveries and, for events
// indicating a session is no longer valid (logout, deletion, anonymisation),
// drops any cached LoginSession bound to the user. The shared secret is
// required: routes are not registered when [WithDiscourseWebhook] is unset.
//
// Discourse posts JSON; the signature lives in X-Discourse-Event-Signature
// formatted as `sha256=<hex>` and covers the raw body bytes. We never
// process the body before verifying the signature.
func (o *OIDCProvider) webhookEndpoint(rw http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(rw, req.Body, maxWebhookBodyBytes))
	if err != nil {
		log.Warn().Err(err).Msg("webhook body read failed")
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}

	sigHeader := req.Header.Get("X-Discourse-Event-Signature")
	if !verifyDiscourseSignature(o.webhookSecret, body, sigHeader) {
		log.Warn().Str("event", req.Header.Get("X-Discourse-Event")).Msg("webhook signature rejected")
		http.Error(rw, "invalid signature", http.StatusUnauthorized)
		return
	}

	event := req.Header.Get("X-Discourse-Event")
	if event == "" {
		// Discourse's first delivery is a "ping" type with X-Discourse-Event-Type=ping
		// and no event name; accept it as a no-op so operators can use the
		// "Test" button in the UI.
		if req.Header.Get("X-Discourse-Event-Type") == "ping" {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(rw, "missing event header", http.StatusBadRequest)
		return
	}

	if !isLogoutEquivalent(event) {
		// Other events (user_created, etc.) are ignored for now but
		// acknowledged so Discourse stops retrying.
		log.Debug().Str("event", event).Msg("webhook event ignored")
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	subject, err := extractUserSubject(body)
	if err != nil {
		log.Warn().Err(err).Str("event", event).Msg("webhook payload missing user id")
		http.Error(rw, "bad payload", http.StatusBadRequest)
		return
	}

	n, err := o.loginStore.DeleteBySubject(subject)
	if err != nil {
		log.Warn().Err(err).Str("event", event).Str("subject", subject).Msg("webhook session deletion failed")
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Info().Str("event", event).Str("subject", subject).Int("removed", n).Msg("invalidated login sessions via webhook")
	rw.WriteHeader(http.StatusNoContent)
}

// verifyDiscourseSignature compares the supplied `sha256=<hex>` header
// against HMAC-SHA256(secret, body) in constant time. Returns false on
// any parse failure so a malformed header rejects rather than throws.
func verifyDiscourseSignature(secret, body []byte, header string) bool {
	if len(secret) == 0 || header == "" {
		return false
	}
	parts := strings.SplitN(header, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return false
	}
	want, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, secret)
	h.Write(body)
	return hmac.Equal(h.Sum(nil), want)
}

// isLogoutEquivalent returns true for Discourse events that indicate
// any cached identity for the user is no longer trustworthy. We accept
// a small allow-list rather than reacting to every event so future
// Discourse changes don't silently expand the blast radius.
func isLogoutEquivalent(event string) bool {
	switch event {
	case "user_logged_out", "user_destroyed", "user_suspended", "user_anonymized":
		return true
	}
	return false
}

// extractUserSubject pulls the user id out of a Discourse user-event
// payload. Discourse wraps the user object under `user` for user_*
// events; the id is a JSON number that must be normalised to the same
// string form the SSO `external_id` field uses (decimal, no leading
// zeros) so DeleteBySubject matches.
func extractUserSubject(body []byte) (string, error) {
	var envelope struct {
		User struct {
			ID json.Number `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", err
	}
	if envelope.User.ID == "" {
		return "", errors.New("webhook payload missing user.id")
	}
	n, err := strconv.ParseInt(envelope.User.ID.String(), 10, 64)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(n, 10), nil
}
