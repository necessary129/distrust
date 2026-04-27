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
	sso, sig := signedSSO(t, key, "nonce=123&username=alice&groups=team")

	values, err := ValidateResponse(sso, sig, key, 123)
	if err != nil {
		t.Fatalf("expected valid response, got error: %v", err)
	}

	if got, want := values.Get("username"), "alice"; got != want {
		t.Fatalf("username mismatch: got %q want %q", got, want)
	}
}

func TestValidateResponseInvalidSignature(t *testing.T) {
	const key = "topsecret"
	sso, _ := signedSSO(t, key, "nonce=123&username=alice")

	_, err := ValidateResponse(sso, "deadbeef", key, 123)
	if err == nil {
		t.Fatal("expected signature validation error, got nil")
	}
}

func TestValidateResponseInvalidNonce(t *testing.T) {
	const key = "topsecret"
	sso, sig := signedSSO(t, key, "nonce=123&username=alice")

	_, err := ValidateResponse(sso, sig, key, 321)
	if err == nil {
		t.Fatal("expected nonce validation error, got nil")
	}
}
