package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/parkour-vienna/distrust/discourse"
)

func TestStoreAndPopInFlight(t *testing.T) {
	provider := &OIDCProvider{inflight: map[uuid.UUID]*InFlightRequest{}}
	id := uuid.New()
	want := &InFlightRequest{Nonce: "abc123", ExpiresAt: time.Now().Add(time.Minute)}

	provider.storeInFlight(id, want)

	got, ok := provider.popInFlight(id)
	if !ok {
		t.Fatal("expected in-flight request to exist")
	}
	if got.Nonce != want.Nonce {
		t.Fatalf("nonce mismatch: got %q want %q", got.Nonce, want.Nonce)
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

	provider.storeInFlight(expiredID, &InFlightRequest{Nonce: "old", ExpiresAt: now.Add(-time.Second)})
	provider.storeInFlight(activeID, &InFlightRequest{Nonce: "new", ExpiresAt: now.Add(time.Minute)})

	provider.purgeExpiredInflight(now)

	if _, ok := provider.popInFlight(expiredID); ok {
		t.Fatal("expected expired request to be removed")
	}
	if _, ok := provider.popInFlight(activeID); !ok {
		t.Fatal("expected active request to remain")
	}
}

func TestSplitGroups(t *testing.T) {
	if got := splitGroups(""); got != nil {
		t.Fatalf("expected nil for empty input, got %#v", got)
	}
	got := splitGroups("a,b,c")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected split: %#v", got)
	}
}

func TestParseEmailVerified(t *testing.T) {
	cases := map[string]bool{
		"":      true,
		"true":  true,
		"TRUE":  true,
		"false": false,
		"False": false,
		"0":     false,
		"no":    false,
		"yes":   true,
	}
	for in, want := range cases {
		if got := parseEmailVerified(in); got != want {
			t.Fatalf("parseEmailVerified(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidateDiscoursePayload(t *testing.T) {
	good := func() map[string][]string {
		return map[string][]string{
			"external_id": {"42"},
			"username":    {"alice"},
			"email":       {"alice@example.org"},
		}
	}
	if err := validateDiscoursePayload(good()); err != nil {
		t.Fatalf("good payload rejected: %v", err)
	}

	missing := good()
	delete(missing, "username")
	if err := validateDiscoursePayload(missing); err == nil {
		t.Fatal("expected missing-username to be rejected")
	}

	nonNumeric := good()
	nonNumeric["external_id"] = []string{"abc"}
	if err := validateDiscoursePayload(nonNumeric); err == nil {
		t.Fatal("expected non-numeric external_id to be rejected")
	}

	tooLong := good()
	tooLong["name"] = []string{strings.Repeat("a", maxClaimFieldBytes+1)}
	if err := validateDiscoursePayload(tooLong); err == nil {
		t.Fatal("expected oversized name to be rejected")
	}

	badEmail := good()
	badEmail["email"] = []string{"not-an-email"}
	if err := validateDiscoursePayload(badEmail); err == nil {
		t.Fatal("expected malformed email to be rejected")
	}
}

func TestNewOIDCRequiresFullConfig(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	good := []byte("0123456789abcdef0123456789abcdef")
	disc := discourse.SSOConfig{Server: "https://forum.example", Secret: "x"}
	clients := map[string]fosite.Client{}

	tests := []struct {
		name    string
		opts    []OIDCOption
		wantSub string
	}{
		{"missing private key", []OIDCOption{WithIssuer("https://x.example/oauth2"), WithSecret(good)}, "private key"},
		{"missing secret", []OIDCOption{WithIssuer("https://x.example/oauth2"), WithPrivateKey(priv)}, "secret"},
		{"short secret", []OIDCOption{WithIssuer("https://x.example/oauth2"), WithPrivateKey(priv), WithSecret([]byte("too-short"))}, "32 bytes"},
		{"missing issuer", []OIDCOption{WithPrivateKey(priv), WithSecret(good)}, "issuer is required"},
		{"non-http issuer", []OIDCOption{WithIssuer("ftp://x.example/oauth2"), WithPrivateKey(priv), WithSecret(good)}, "absolute http"},
		{"empty-host issuer", []OIDCOption{WithIssuer("https:///oauth2"), WithPrivateKey(priv), WithSecret(good)}, "absolute http"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewOIDC("/oauth2", disc, clients, tc.opts...)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}

	t.Run("happy path", func(t *testing.T) {
		p, err := NewOIDC("/oauth2", disc, clients,
			WithIssuer("https://x.example/oauth2"), WithPrivateKey(priv), WithSecret(good))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !p.cookieSecure {
			t.Fatal("expected cookieSecure=true for https issuer")
		}
		if p.issuer != "https://x.example/oauth2" {
			t.Fatalf("issuer mismatch: %q", p.issuer)
		}
	})

	t.Run("http issuer disables cookie Secure", func(t *testing.T) {
		p, err := NewOIDC("/oauth2", disc, clients,
			WithIssuer("http://localhost:3000/oauth2"), WithPrivateKey(priv), WithSecret(good))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.cookieSecure {
			t.Fatal("expected cookieSecure=false for http issuer")
		}
	})

	t.Run("trailing slash trimmed", func(t *testing.T) {
		p, err := NewOIDC("/oauth2", disc, clients,
			WithIssuer("https://x.example/oauth2/"), WithPrivateKey(priv), WithSecret(good))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.issuer != "https://x.example/oauth2" {
			t.Fatalf("expected trailing slash trimmed, got %q", p.issuer)
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
