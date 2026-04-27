package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/parkour-vienna/distrust/discourse"
)

func newIntegrationProviderAndRouter(t *testing.T) (*OIDCProvider, http.Handler) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test private key: %v", err)
	}

	clients := map[string]fosite.Client{
		"test-client": &DistrustClient{
			DefaultClient: fosite.DefaultClient{
				ID:            "test-client",
				Secret:        []byte("unused-in-auth-code-flow"),
				RedirectURIs:  []string{"https://client.example/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"authorization_code", "refresh_token"},
				Scopes:        []string{"openid"},
			},
		},
	}

	provider, err := NewOIDC(
		"/oauth2",
		discourse.SSOConfig{Server: "https://forum.example", Secret: "disc-secret"},
		clients,
		WithIssuer("https://distrust.example/oauth2"),
		WithPrivateKey(priv),
		WithSecret([]byte("0123456789abcdef0123456789abcdef")),
	)
	if err != nil {
		t.Fatalf("failed to construct provider: %v", err)
	}

	r := chi.NewRouter()
	r.Route("/oauth2", provider.RegisterHandlers)
	return provider, r
}

func signDiscourseSSO(t *testing.T, secret, payload string) (string, string) {
	t.Helper()

	sso := base64.StdEncoding.EncodeToString([]byte(payload))
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(sso))
	if err != nil {
		t.Fatalf("failed to hash sso payload: %v", err)
	}
	sig := hex.EncodeToString(h.Sum(nil))
	return sso, sig
}

func TestAuthEndpointSetsCookieSecurityAttributes(t *testing.T) {
	_, router := newIntegrationProviderAndRouter(t)

	u := "/oauth2/auth?client_id=test-client&response_type=code&scope=openid&state=state-123456789&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code < 300 || res.Code >= 400 {
		t.Fatalf("expected redirect status, got %d", res.Code)
	}

	loc := res.Header().Get("Location")
	if !strings.Contains(loc, "https://forum.example/session/sso_provider") {
		t.Fatalf("unexpected redirect location: %q", loc)
	}

	result := res.Result()
	defer result.Body.Close()
	var sessionCookie *http.Cookie
	for _, c := range result.Cookies() {
		if c.Name == "oidc_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected oidc_session cookie")
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("expected oidc_session cookie to be HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Fatal("expected oidc_session cookie to be Secure")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("same-site mismatch: got %v want %v", sessionCookie.SameSite, http.SameSiteLaxMode)
	}
	if sessionCookie.Path != "/oauth2" {
		t.Fatalf("cookie path mismatch: got %q want %q", sessionCookie.Path, "/oauth2")
	}
}

func TestCallbackEndpointSuccessAndReplayRejection(t *testing.T) {
	provider, router := newIntegrationProviderAndRouter(t)

	authURL := "/oauth2/auth?client_id=test-client&response_type=code&scope=openid&state=state-123456789&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback"
	authReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	authReq.Header.Set("X-Forwarded-Proto", "https")
	authRes := httptest.NewRecorder()
	router.ServeHTTP(authRes, authReq)
	if authRes.Code < 300 || authRes.Code >= 400 {
		t.Fatalf("expected auth redirect status, got %d", authRes.Code)
	}
	if loc := authRes.Header().Get("Location"); !strings.Contains(loc, "https://forum.example/session/sso_provider") {
		t.Fatalf("unexpected auth redirect location: %q", loc)
	}

	var sessionCookie *http.Cookie
	for _, c := range authRes.Result().Cookies() {
		if c.Name == "oidc_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected oidc_session cookie from auth endpoint")
	}

	sessionID, err := uuid.Parse(sessionCookie.Value)
	if err != nil {
		t.Fatalf("invalid session id cookie: %v", err)
	}

	provider.inflightMu.Lock()
	inflightReq, ok := provider.inflight[sessionID]
	provider.inflightMu.Unlock()
	if !ok {
		t.Fatal("expected session to be present in in-flight store")
	}

	payload := "nonce=" + url.QueryEscape(inflightReq.Nonce) +
		"&external_id=1&username=alice&email=alice%40example.org&name=Alice&groups=team"
	sso, sig := signDiscourseSSO(t, "disc-secret", payload)
	q := url.Values{}
	q.Set("sso", sso)
	q.Set("sig", sig)

	cbReq := httptest.NewRequest(http.MethodGet, "/oauth2/callback?"+q.Encode(), nil)
	cbReq.Header.Set("X-Forwarded-Proto", "https")
	cbReq.AddCookie(sessionCookie)
	cbRes := httptest.NewRecorder()
	router.ServeHTTP(cbRes, cbReq)

	if cbRes.Code < 300 || cbRes.Code >= 400 {
		t.Fatalf("expected redirect status from callback, got %d", cbRes.Code)
	}

	provider.inflightMu.Lock()
	_, stillPresent := provider.inflight[sessionID]
	provider.inflightMu.Unlock()
	if stillPresent {
		t.Fatal("expected session to be consumed and removed after callback")
	}

	replayReq := httptest.NewRequest(http.MethodGet, "/oauth2/callback?"+q.Encode(), nil)
	replayReq.AddCookie(sessionCookie)
	replayRes := httptest.NewRecorder()
	router.ServeHTTP(replayRes, replayReq)

	if replayRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected replay response status 401, got %d", replayRes.Code)
	}
	if !strings.Contains(replayRes.Body.String(), "invalid session") {
		t.Fatalf("expected invalid session response, got %q", replayRes.Body.String())
	}
}

func TestCallbackEndpointRejectsExpiredSession(t *testing.T) {
	provider, router := newIntegrationProviderAndRouter(t)

	sessionID := uuid.New()
	provider.storeInFlight(sessionID, &InFlightRequest{Nonce: "x", ExpiresAt: time.Now().Add(-time.Second)})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?sso=a&sig=b", nil)
	req.AddCookie(&http.Cookie{Name: "oidc_session", Value: sessionID.String()})
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status mismatch: got %d want %d", res.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(res.Body.String(), "invalid session") {
		t.Fatalf("expected invalid session response, got %q", res.Body.String())
	}
}

