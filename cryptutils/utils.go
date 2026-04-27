package cryptutils

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
)

// KeyID returns a stable JWK `kid` derived from the public key. RawURLEncoding
// is used so the result is safe to embed in URLs and JWS headers without
// further escaping; the previous truncated StdEncoding output mixed `+` and
// `/` characters that were brittle when consumers handled the kid as a path
// segment.
func KeyID(pub rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(&pub)
	h := crypto.SHA256.New()
	h.Write(der)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
