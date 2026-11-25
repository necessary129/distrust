package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"
	"github.com/parkour-vienna/distrust/discourse"
	"golang.org/x/crypto/bcrypt"
)

const guardMaxFailures = 3

func newClientAuthProviderAndRouter(t *testing.T) http.Handler {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("right"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	clients := map[string]fosite.Client{
		"svc": &DistrustClient{DefaultClient: fosite.DefaultClient{
			ID:           "svc",
			Secret:       hash,
			RedirectURIs: []string{"https://svc.example/cb"},
			GrantTypes:   []string{"client_credentials"},
			Scopes:       []string{"openid"},
		}},
	}
	provider, err := NewOIDC("/oauth2",
		discourse.SSOConfig{Server: "https://forum.example", Secret: "disc-secret"},
		clients,
		WithIssuer("https://distrust.example/oauth2"),
		WithPrivateKey(priv),
		WithSecret([]byte("0123456789abcdef0123456789abcdef")),
		WithClientAuthFailureLimit(guardMaxFailures, time.Minute),
	)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
	r := chi.NewRouter()
	r.Route("/oauth2", provider.RegisterHandlers)
	return r
}

func postClientCredentials(h http.Handler, path, from, secret string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"client_credentials"}, "token": {"x"}}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = from + ":1234"
	req.SetBasicAuth("svc", secret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestClientAuthGuardBlocksAfterRepeatedFailures(t *testing.T) {
	h := newClientAuthProviderAndRouter(t)

	for i := 0; i < guardMaxFailures; i++ {
		if rr := postClientCredentials(h, "/oauth2/token", "198.51.100.1", "wrong"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: got %d want 401", i+1, rr.Code)
		}
	}

	// Over budget: rejected before the secret is checked, even a correct one.
	rr := postClientCredentials(h, "/oauth2/token", "198.51.100.1", "right")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
	if !strings.Contains(rr.Body.String(), "temporarily_unavailable") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}

	// The budget is per address and shared across the guarded endpoints.
	for _, path := range []string{"/oauth2/introspect", "/oauth2/revoke"} {
		if rr := postClientCredentials(h, path, "198.51.100.1", "right"); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("%s: got %d want 429", path, rr.Code)
		}
	}
	if rr := postClientCredentials(h, "/oauth2/token", "198.51.100.2", "right"); rr.Code != http.StatusOK {
		t.Fatalf("other address: got %d want 200 (%s)", rr.Code, rr.Body.String())
	}
}

func TestClientAuthGuardIgnoresSuccesses(t *testing.T) {
	h := newClientAuthProviderAndRouter(t)
	for i := 0; i < 3*guardMaxFailures; i++ {
		if rr := postClientCredentials(h, "/oauth2/token", "198.51.100.1", "right"); rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d want 200 (%s)", i+1, rr.Code, rr.Body.String())
		}
	}
}

func TestClientAuthGuardNilIsNoop(t *testing.T) {
	var g *clientAuthGuard
	called := false
	g.wrap(func(http.ResponseWriter, *http.Request) { called = true })(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))
	if !called {
		t.Fatal("nil guard should pass through")
	}
}
