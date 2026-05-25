package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

func newWebhookProviderAndRouter(t *testing.T, secret string) (*OIDCProvider, http.Handler) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	provider, err := NewOIDC("/oauth2",
		discourse.SSOConfig{Server: "https://forum.example", Secret: "disc-secret"},
		map[string]fosite.Client{},
		WithIssuer("https://distrust.example/oauth2"),
		WithPrivateKey(priv),
		WithSecret([]byte("0123456789abcdef0123456789abcdef")),
		WithDiscourseWebhook(secret),
	)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	r := chi.NewRouter()
	r.Route("/oauth2", provider.RegisterHandlers)
	return provider, r
}

func signBody(secret string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func TestWebhookEndpointNotRegisteredWithoutSecret(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	provider, err := NewOIDC("/oauth2",
		discourse.SSOConfig{Server: "https://forum.example", Secret: "x"},
		map[string]fosite.Client{},
		WithIssuer("https://distrust.example/oauth2"),
		WithPrivateKey(priv),
		WithSecret([]byte("0123456789abcdef0123456789abcdef")),
	)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	r := chi.NewRouter()
	r.Route("/oauth2", provider.RegisterHandlers)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/webhook", strings.NewReader("{}"))
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed && res.Code != http.StatusNotFound {
		t.Fatalf("expected webhook route to be unregistered (404/405), got %d", res.Code)
	}
}

func TestWebhookRejectsMissingSignature(t *testing.T) {
	_, router := newWebhookProviderAndRouter(t, "shared-secret")
	body := []byte(`{"user":{"id":1}}`)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Discourse-Event", "user_logged_out")
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}

func TestWebhookRejectsWrongSignature(t *testing.T) {
	_, router := newWebhookProviderAndRouter(t, "shared-secret")
	body := []byte(`{"user":{"id":1}}`)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Discourse-Event", "user_logged_out")
	req.Header.Set("X-Discourse-Event-Signature", signBody("other-secret", body))
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}

func TestWebhookLogoutDeletesMatchingSessions(t *testing.T) {
	provider, router := newWebhookProviderAndRouter(t, "shared-secret")

	idA1 := uuid.New()
	idA2 := uuid.New()
	idB := uuid.New()
	mk := func(sub string) *LoginSession {
		return &LoginSession{
			AuthTime:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			Values:    url.Values{"external_id": {sub}, "username": {"u" + sub}},
		}
	}
	if err := provider.loginStore.Store(idA1, mk("101")); err != nil {
		t.Fatal(err)
	}
	if err := provider.loginStore.Store(idA2, mk("101")); err != nil {
		t.Fatal(err)
	}
	if err := provider.loginStore.Store(idB, mk("202")); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"user":{"id":101,"username":"u101"}}`)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Discourse-Event", "user_logged_out")
	req.Header.Set("X-Discourse-Event-Signature", signBody("shared-secret", body))
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body=%q)", res.Code, res.Body.String())
	}

	if _, ok := provider.loginStore.Lookup(idA1); ok {
		t.Fatal("expected idA1 to be deleted")
	}
	if _, ok := provider.loginStore.Lookup(idA2); ok {
		t.Fatal("expected idA2 to be deleted")
	}
	if _, ok := provider.loginStore.Lookup(idB); !ok {
		t.Fatal("expected idB (different user) to remain")
	}
}

func TestWebhookIgnoredEventsAcked(t *testing.T) {
	_, router := newWebhookProviderAndRouter(t, "shared-secret")
	body := []byte(`{"user":{"id":1}}`)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Discourse-Event", "user_created")
	req.Header.Set("X-Discourse-Event-Signature", signBody("shared-secret", body))
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for ignored event, got %d", res.Code)
	}
}

func TestWebhookPingAccepted(t *testing.T) {
	_, router := newWebhookProviderAndRouter(t, "shared-secret")
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Discourse-Event-Type", "ping")
	req.Header.Set("X-Discourse-Event-Signature", signBody("shared-secret", body))
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for ping, got %d", res.Code)
	}
}
