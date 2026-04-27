package discourse

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

type SSOConfig struct {
	Server string
	Secret string
}

func GenerateURL(server, callback, key string, nonce int) string {
	payload := fmt.Sprintf("nonce=%d&return_sso_url=%s", nonce, callback)
	rk := []byte(key)
	bpl := make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
	base64.StdEncoding.Encode(bpl, []byte(payload))
	h := hmac.New(sha256.New, rk)
	h.Write(bpl)

	return fmt.Sprintf("%s/session/sso_provider?sso=%s&sig=%s",
		server,
		string(bpl),
		hex.EncodeToString(h.Sum(nil)))
}

func ValidateResponse(sso, sig, key string, nonce int) (url.Values, error) {
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

	rnonce, err := strconv.Atoi(values.Get("nonce"))
	if err != nil {
		return nil, fmt.Errorf("parsing returned nonce: %w", err)
	}

	if subtle.ConstantTimeEq(int32(rnonce), int32(nonce)) != 1 {
		return nil, errors.New("wrong nonce from discourse")
	}

	return values, nil
}
