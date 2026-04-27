package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestStoreAndPopInFlight(t *testing.T) {
	provider := &OIDCProvider{inflight: map[uuid.UUID]*InFlightRequest{}}
	id := uuid.New()
	want := &InFlightRequest{Nonce: 42, ExpiresAt: time.Now().Add(time.Minute)}

	provider.storeInFlight(id, want)

	got, ok := provider.popInFlight(id)
	if !ok {
		t.Fatal("expected in-flight request to exist")
	}
	if got.Nonce != want.Nonce {
		t.Fatalf("nonce mismatch: got %d want %d", got.Nonce, want.Nonce)
	}

	_, ok = provider.popInFlight(id)
	if ok {
		t.Fatal("expected in-flight request to be removed after pop")
	}
}

func TestPurgeExpiredInflight(t *testing.T) {
	provider := &OIDCProvider{inflight: map[uuid.UUID]*InFlightRequest{}}
	expiredID := uuid.New()
	activeID := uuid.New()
	now := time.Now()

	provider.storeInFlight(expiredID, &InFlightRequest{ExpiresAt: now.Add(-time.Second)})
	provider.storeInFlight(activeID, &InFlightRequest{ExpiresAt: now.Add(time.Minute)})

	provider.purgeExpiredInflight(now)

	if _, ok := provider.popInFlight(expiredID); ok {
		t.Fatal("expected expired request to be removed")
	}
	if _, ok := provider.popInFlight(activeID); !ok {
		t.Fatal("expected active request to remain")
	}
}

func TestRequestScheme(t *testing.T) {
	t.Run("tls request is https", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.TLS = &tls.ConnectionState{}
		if got := requestScheme(req); got != "https" {
			t.Fatalf("scheme mismatch: got %q want %q", got, "https")
		}
	})

	t.Run("valid forwarded proto is used", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		if got := requestScheme(req); got != "https" {
			t.Fatalf("scheme mismatch: got %q want %q", got, "https")
		}
	})

	t.Run("invalid forwarded proto falls back to http", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("X-Forwarded-Proto", "javascript")
		if got := requestScheme(req); got != "http" {
			t.Fatalf("scheme mismatch: got %q want %q", got, "http")
		}
	})

	t.Run("uses first forwarded proto value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("X-Forwarded-Proto", "https, http")
		if got := requestScheme(req); got != "https" {
			t.Fatalf("scheme mismatch: got %q want %q", got, "https")
		}
	})
}

func TestRegisterHandlersMethodRestrictions(t *testing.T) {
	provider := &OIDCProvider{}
	r := chi.NewRouter()
	provider.RegisterHandlers(r)

	t.Run("token endpoint rejects GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status mismatch: got %d want %d", rr.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("revoke endpoint rejects GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/revoke", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status mismatch: got %d want %d", rr.Code, http.StatusMethodNotAllowed)
		}
	})
}
