package discourse

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
)

type SSOConfig struct {
	Server string
	Secret string
}

// NewNonce returns a 128-bit random nonce as a hex string. 128 bits keeps
// guessing infeasible across the entire deployment lifetime; the nonce is
// also bound to a session cookie and HMAC, so this is defense-in-depth.
func NewNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func GenerateURL(server, callback, key, nonce string) string {
	payload := fmt.Sprintf("nonce=%s&return_sso_url=%s", url.QueryEscape(nonce), url.QueryEscape(callback))
	rk := []byte(key)
	bpl := make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
	base64.StdEncoding.Encode(bpl, []byte(payload))
	h := hmac.New(sha256.New, rk)
	h.Write(bpl)

	return fmt.Sprintf("%s/session/sso_provider?sso=%s&sig=%s",
		server,
		url.QueryEscape(string(bpl)),
		hex.EncodeToString(h.Sum(nil)))
}

// maxSSOPayloadBytes caps the size of an inbound base64-encoded Discourse SSO
// payload to bound the work done before HMAC verification and prevent memory
// blowups from pathological responses.
const maxSSOPayloadBytes = 8 * 1024

func ValidateResponse(sso, sig, key, nonce string) (url.Values, error) {
	if len(sso) > maxSSOPayloadBytes {
		return nil, errors.New("discourse sso payload too large")
	}
	rk := []byte(key)
	h := hmac.New(sha256.New, rk)
	h.Write([]byte(sso))

	rsig, err := hex.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	if subtle.ConstantTimeCompare(h.Sum(nil), rsig) != 1 {
		return nil, errors.New("wrong signature from discourse")
	}

	qs, err := base64.StdEncoding.DecodeString(sso)
	if err != nil {
		return nil, fmt.Errorf("decoding discourse payload: %w", err)
	}
	values, err := url.ParseQuery(string(qs))
	if err != nil {
		return nil, fmt.Errorf("parsing discourse payload: %w", err)
	}

	rnonce := values.Get("nonce")
	if subtle.ConstantTimeCompare([]byte(rnonce), []byte(nonce)) != 1 {
		return nil, errors.New("wrong nonce from discourse")
	}

	return values, nil
}
