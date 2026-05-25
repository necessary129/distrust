package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/parkour-vienna/distrust/cryptutils"
	"github.com/parkour-vienna/distrust/discourse"
	"github.com/rs/zerolog/log"
)

type OIDCProvider struct {
	oauth2          fosite.OAuth2Provider
	inflight        map[uuid.UUID]*InFlightRequest
	inflightMu      sync.Mutex
	loginStore      LoginSessionStore
	webhookSecret   []byte
	root            string
	issuer          string
	cookieSecure    bool
	discourseServer string
	discourseSecret string
	privateKey      *rsa.PrivateKey
	keyID           string

	// Precomputed response bodies for the well-known endpoints. These never
	// change once the provider is constructed and are served verbatim.
	discoveryJSON []byte
	jwksJSON      []byte

	authRateLimit func(http.Handler) http.Handler

	janitorStop chan struct{}
	janitorDone chan struct{}
}

type DistrustClient struct {
	fosite.DefaultClient
	AllowGroups []string
	DenyGroups  []string
}

type InFlightRequest struct {
	Nonce     string
	ExpiresAt time.Time
	Ar        fosite.AuthorizeRequester
}

// LoginSession records a successful Discourse SSO authentication so that
// subsequent /auth requests with prompt=none can mint tokens without a
// fresh Discourse round-trip. AuthTime is the timestamp recorded at the
// /callback that established the session and is used as the `auth_time`
// claim plus the input to fosite's prompt=none/max_age validation.
type LoginSession struct {
	AuthTime  time.Time
	ExpiresAt time.Time
	Values    url.Values
}

// loginSessionTTL bounds how long a silent re-authentication can succeed
// after the last interactive Discourse login. Set to roughly match
// Discourse's default cookie lifetime so the local session is unlikely
// to outlive the upstream session it stands in for.
const loginSessionTTL = 24 * time.Hour

// loginCookieName is the cookie that pins a browser to a LoginSession.
// Distinct from oidc_session (per-flow, 10-minute) so they coexist.
const loginCookieName = "distrust_login"

type oidcOptions struct {
	privateKey    *rsa.PrivateKey
	secret        []byte
	issuer        string
	authRateLimit func(http.Handler) http.Handler
	sessionDB     string
	webhookSecret []byte
}

type funcOIDCOption struct {
	f func(*oidcOptions)
}

func (fo *funcOIDCOption) apply(oo *oidcOptions) {
	fo.f(oo)
}

type OIDCOption interface {
	apply(do *oidcOptions)
}

// NewOIDC constructs an OIDC provider. It returns an error if the supplied
// configuration is incomplete or invalid; previously these were silently
// downgraded to ephemeral defaults (random key, random secret) which made
// misconfiguration invisible until tokens started failing on restart.
func NewOIDC(path string, disc discourse.SSOConfig, clients map[string]fosite.Client, opts ...OIDCOption) (*OIDCProvider, error) {
	s := storage.NewMemoryStore()
	s.Clients = clients
	oopts := oidcOptions{}
	for _, opt := range opts {
		opt.apply(&oopts)
	}

	if oopts.privateKey == nil {
		return nil, errors.New("oidc: private key is required (use auth.WithPrivateKey)")
	}
	if len(oopts.secret) != 32 {
		return nil, fmt.Errorf("oidc: secret must be exactly 32 bytes long, got %d", len(oopts.secret))
	}
	if oopts.issuer == "" {
		return nil, errors.New("oidc: issuer is required (use auth.WithIssuer)")
	}
	u, err := url.Parse(oopts.issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("oidc: issuer must be an absolute http(s) URL, got %q", oopts.issuer)
	}

	config := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        oopts.secret,
	}
	var loginStore LoginSessionStore
	if oopts.sessionDB != "" {
		ls, err := newSQLiteSessionStore(oopts.sessionDB)
		if err != nil {
			return nil, fmt.Errorf("opening session db: %w", err)
		}
		loginStore = ls
	} else {
		loginStore = newMemorySessionStore()
	}

	provider := &OIDCProvider{
		oauth2:          compose.ComposeAllEnabled(config, s, oopts.privateKey),
		inflight:        map[uuid.UUID]*InFlightRequest{},
		loginStore:      loginStore,
		webhookSecret:   oopts.webhookSecret,
		root:            path,
		issuer:          strings.TrimRight(oopts.issuer, "/"),
		cookieSecure:    u.Scheme == "https",
		privateKey:      oopts.privateKey,
		keyID:           cryptutils.KeyID(oopts.privateKey.PublicKey),
		discourseServer: disc.Server,
		discourseSecret: disc.Secret,
		authRateLimit:   oopts.authRateLimit,
	}
	if err := provider.precomputeDiscovery(); err != nil {
		_ = loginStore.Close()
		return nil, fmt.Errorf("precomputing discovery document: %w", err)
	}
	provider.startInflightJanitor()
	return provider, nil
}

func WithPrivateKey(p *rsa.PrivateKey) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.privateKey = p
		},
	}
}

func WithSecret(s []byte) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.secret = s
		},
	}
}

// WithIssuer sets the public issuer URL advertised in OIDC discovery and as
// the `iss` claim in tokens. Required.
func WithIssuer(s string) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.issuer = s
		},
	}
}

// WithAuthRateLimiter installs a middleware that wraps the user-initiated
// /auth and /callback endpoints. If unset, those endpoints are unlimited.
func WithAuthRateLimiter(mw func(http.Handler) http.Handler) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.authRateLimit = mw
		},
	}
}

// WithSessionDB enables SQLite-backed persistence of login sessions
// (the records that back silent prompt=none re-authentication). If
// unset, sessions live in process memory and are lost on restart.
func WithSessionDB(path string) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.sessionDB = path
		},
	}
}

// WithDiscourseWebhook enables the /webhook endpoint and sets the
// shared secret used to verify the X-Discourse-Event-Signature
// header on incoming events. Supply the same string configured in
// Discourse's webhook UI. Empty disables the endpoint.
func WithDiscourseWebhook(secret string) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.webhookSecret = []byte(secret)
		},
	}
}

// maxOAuthRequestBodyBytes caps the size of POST request bodies on OAuth2
// endpoints. 64 KiB is far above any legitimate token/introspect/revoke payload
// (well under typical assertion sizes used in client_credentials grants too)
// and bounds memory cost of malicious or malformed clients.
const maxOAuthRequestBodyBytes = 64 * 1024

func limitBody(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(rw, req.Body, maxOAuthRequestBodyBytes)
		h(rw, req)
	}
}

func (o *OIDCProvider) RegisterHandlers(r chi.Router) {
	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	authR := r
	if o.authRateLimit != nil {
		authR = r.With(o.authRateLimit)
	}
	authR.Get("/auth", o.authEndpoint)
	authR.Get("/callback", o.callbackEndpoint)
	r.Post("/token", limitBody(o.tokenEndpoint))
	r.Post("/introspect", limitBody(o.introspectionEndpoint))
	r.MethodFunc(http.MethodGet, "/userinfo", o.userInfoEndpoint)
	r.MethodFunc(http.MethodPost, "/userinfo", limitBody(o.userInfoEndpoint))

	// revoke tokens
	r.Post("/revoke", limitBody(o.revokeEndpoint))

	r.Get("/.well-known/openid-configuration", o.informationEndpoint)
	r.Get("/certs", o.certsEndpoint)

	// Only expose the webhook receiver if a shared secret was supplied,
	// so a misconfigured deployment can't accept unsigned event posts.
	if len(o.webhookSecret) > 0 {
		r.Post("/webhook", limitBody(o.webhookEndpoint))
	}
}

func (o *OIDCProvider) storeInFlight(sessionID uuid.UUID, req *InFlightRequest) {
	o.inflightMu.Lock()
	defer o.inflightMu.Unlock()
	o.inflight[sessionID] = req
}

func (o *OIDCProvider) popInFlight(sessionID uuid.UUID) (*InFlightRequest, bool) {
	o.inflightMu.Lock()
	defer o.inflightMu.Unlock()
	req, ok := o.inflight[sessionID]
	if ok {
		delete(o.inflight, sessionID)
	}
	return req, ok
}

func (o *OIDCProvider) purgeExpiredInflight(now time.Time) {
	o.inflightMu.Lock()
	defer o.inflightMu.Unlock()
	for id, req := range o.inflight {
		if now.After(req.ExpiresAt) {
			delete(o.inflight, id)
		}
	}
}

func (o *OIDCProvider) storeLoginSession(sessionID uuid.UUID, s *LoginSession) {
	if err := o.loginStore.Store(sessionID, s); err != nil {
		// The interactive flow has already completed; failing to write
		// the silent-auth session only degrades a future prompt=none to
		// login_required, which is the correct fallback.
		log.Warn().Err(err).Msg("login session store failed")
	}
}

// lookupLoginSession returns the session without consuming it: a single
// login should be reusable across multiple silent /auth requests within
// its TTL. Expired entries are returned as (nil, false) and proactively
// reaped by the store so callers cannot resurrect them.
func (o *OIDCProvider) lookupLoginSession(sessionID uuid.UUID) (*LoginSession, bool) {
	return o.loginStore.Lookup(sessionID)
}

func (o *OIDCProvider) purgeExpiredLoginSessions(now time.Time) {
	if err := o.loginStore.PurgeExpired(now); err != nil {
		log.Warn().Err(err).Msg("login session purge failed")
	}
}

func (o *OIDCProvider) startInflightJanitor() {
	o.janitorStop = make(chan struct{})
	o.janitorDone = make(chan struct{})
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		defer close(o.janitorDone)
		for {
			select {
			case <-o.janitorStop:
				return
			case now := <-ticker.C:
				o.purgeExpiredInflight(now)
				o.purgeExpiredLoginSessions(now)
			}
		}
	}()
}

func (o *OIDCProvider) precomputeDiscovery() error {
	discovery := map[string]interface{}{
		"issuer":                 o.issuer,
		"authorization_endpoint": o.issuer + "/auth",
		"token_endpoint":         o.issuer + "/token",
		"userinfo_endpoint":      o.issuer + "/userinfo",
		"jwks_uri":               o.issuer + "/certs",
		"response_types_supported": []string{
			"code",
			"none",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"code id_token token",
		},
		"subject_types_supported":               []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	dj, err := json.Marshal(discovery)
	if err != nil {
		return err
	}
	o.discoveryJSON = dj

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Algorithm: "RS256",
			KeyID:     o.keyID,
			Use:       "sig",
			Key:       &o.privateKey.PublicKey,
		}},
	}
	jj, err := json.Marshal(jwks)
	if err != nil {
		return err
	}
	o.jwksJSON = jj
	return nil
}

// Shutdown stops the in-flight-request janitor and waits for it to exit,
// then closes the login-session store. Idempotent and safe to call from
// a signal handler.
func (o *OIDCProvider) Shutdown(ctx context.Context) error {
	if o.janitorStop != nil {
		select {
		case <-o.janitorStop:
			// already closed
		default:
			close(o.janitorStop)
		}
		select {
		case <-o.janitorDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if o.loginStore != nil {
		if err := o.loginStore.Close(); err != nil {
			return fmt.Errorf("closing login session store: %w", err)
		}
	}
	return nil
}

func (o *OIDCProvider) newSession(aroot string, values url.Values, authTime time.Time) *openid.DefaultSession {
	now := time.Now()
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      aroot,
			Subject:     values.Get("external_id"),
			Audience:    []string{},
			ExpiresAt:   now.Add(time.Hour * 6),
			IssuedAt:    now,
			RequestedAt: now,
			AuthTime:    authTime,
			Extra: map[string]interface{}{
				"email":              values.Get("email"),
				"email_verified":     parseEmailVerified(values.Get("email_verified")),
				"picture":            values.Get("avatar_url"),
				"name":               values.Get("name"),
				"groups":             splitGroups(values.Get("groups")),
				"preferred_username": values.Get("username"),
			},
		},
		Headers: &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": o.keyID,
			},
		},
	}
}

func splitGroups(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// parseEmailVerified honours an optional `email_verified` field from Discourse.
// Discourse only allows SSO logins from accounts whose email has been
// confirmed (or the operator has disabled `must_approve_users`), so defaulting
// to true when the field is absent matches Discourse's behaviour. An explicit
// "false" demotes the claim — useful when an operator has loosened that
// requirement.
func parseEmailVerified(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no":
		return false
	default:
		return true
	}
}
