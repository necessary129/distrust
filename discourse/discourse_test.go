package discourse

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func signedSSO(t *testing.T, key string, payload string) (string, string) {
	t.Helper()
	sso := base64.StdEncoding.EncodeToString([]byte(payload))
	h := hmac.New(sha256.New, []byte(key))
	_, err := h.Write([]byte(sso))
	if err != nil {
		t.Fatalf("failed to write hmac payload: %v", err)
	}
	sig := hex.EncodeToString(h.Sum(nil))
	return sso, sig
}

func TestValidateResponseValid(t *testing.T) {
	const key = "topsecret"
	sso, sig := signedSSO(t, key, "nonce=abc123&username=alice&groups=team")

	values, err := ValidateResponse(sso, sig, key, "abc123")
	if err != nil {
		t.Fatalf("expected valid response, got error: %v", err)
	}

	if got, want := values.Get("username"), "alice"; got != want {
		t.Fatalf("username mismatch: got %q want %q", got, want)
	}
}

func TestValidateResponseInvalidSignature(t *testing.T) {
	const key = "topsecret"
	sso, _ := signedSSO(t, key, "nonce=abc123&username=alice")

	_, err := ValidateResponse(sso, "deadbeef", key, "abc123")
	if err == nil {
		t.Fatal("expected signature validation error, got nil")
	}
}

func TestValidateResponseInvalidNonce(t *testing.T) {
	const key = "topsecret"
	sso, sig := signedSSO(t, key, "nonce=abc123&username=alice")

	_, err := ValidateResponse(sso, sig, key, "deadbeef")
	if err == nil {
		t.Fatal("expected nonce validation error, got nil")
	}
}

func TestValidateResponseRejectsOversizedPayload(t *testing.T) {
	huge := make([]byte, maxSSOPayloadBytes+1)
	for i := range huge {
		huge[i] = 'A'
	}
	_, err := ValidateResponse(string(huge), "deadbeef", "k", "abc")
	if err == nil {
		t.Fatal("expected oversized-payload error, got nil")
	}
}

func TestNewNonceUnique(t *testing.T) {
	a, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	b, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}
	if a == b {
		t.Fatalf("expected unique nonces, got %q twice", a)
	}
	if len(a) != 32 { // 16 bytes hex
		t.Fatalf("expected 32-char hex nonce, got %d chars", len(a))
	}
}
