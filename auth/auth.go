package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
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
	root            string
	discourseServer string
	discourseSecret string
	privateKey      *rsa.PrivateKey
}

type DistrustClient struct {
	fosite.DefaultClient
	AllowGroups []string
	DenyGroups  []string
}

type InFlightRequest struct {
	Nonce     int
	ExpiresAt time.Time
	Ar        fosite.AuthorizeRequester
}

type oidcOptions struct {
	privateKey *rsa.PrivateKey
	secret     []byte
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

func NewOIDC(path string, disc discourse.SSOConfig, clients map[string]fosite.Client, opts ...OIDCOption) *OIDCProvider {
	s := storage.NewMemoryStore()
	s.Clients = clients
	oopts := oidcOptions{}
	for _, opt := range opts {
		opt.apply(&oopts)
	}

	if oopts.secret == nil {
		log.Warn().Msg("no secret specified in oidc provider. When running multiple instances, make sure this secret is the same on all instances")
		var secret = make([]byte, 32)
		_, _ = rand.Read(secret)
		oopts.secret = secret
	}
	if oopts.privateKey == nil {
		log.Warn().Msg("no private key specified in oidc provider. Your tokens will be invalid on restart")
		priv, _ := rsa.GenerateKey(rand.Reader, 3072)
		oopts.privateKey = priv
	}

	config := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        oopts.secret,
	}
	provider := &OIDCProvider{
		oauth2:          compose.ComposeAllEnabled(config, s, oopts.privateKey),
		inflight:        map[uuid.UUID]*InFlightRequest{},
		root:            path,
		privateKey:      oopts.privateKey,
		discourseServer: disc.Server,
		discourseSecret: disc.Secret,
	}
	provider.startInflightJanitor()
	return provider
}

func WithPrivateKey(p *rsa.PrivateKey) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.privateKey = p
		},
	}
}

func WithSecret(s []byte) OIDCOption {
	if len(s) != 32 {
		log.Err(errors.New("invalid secret length")).Msg("secrets must be exactly 32 bytes long. OIDC might not work")
	}
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.secret = s
		},
	}
}

func (o *OIDCProvider) RegisterHandlers(r chi.Router) {
	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	r.Get("/auth", o.authEndpoint)
	r.Get("/callback", o.callbackEndpoint)
	r.Post("/token", o.tokenEndpoint)
	r.Post("/introspect", o.introspectionEndpoint)
	r.MethodFunc(http.MethodGet, "/userinfo", o.userInfoEndpoint)
	r.MethodFunc(http.MethodPost, "/userinfo", o.userInfoEndpoint)

	// revoke tokens
	r.Post("/revoke", o.revokeEndpoint)

	r.Get("/.well-known/openid-configuration", o.informationEndpoint)
	r.Get("/certs", o.certsEndpoint)
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

func (o *OIDCProvider) startInflightJanitor() {
	ticker := time.NewTicker(time.Minute)
	go func() {
		for now := range ticker.C {
			o.purgeExpiredInflight(now)
		}
	}()
}

func (o *OIDCProvider) newSession(aroot string, values url.Values) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      aroot,
			Subject:     values.Get("external_id"),
			Audience:    []string{},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
			Extra: map[string]interface{}{
				"email":              values.Get("email"),
				"email_verified":     true,
				"picture":            values.Get("avatar_url"),
				"name":               values.Get("name"),
				"groups":             strings.Split(values.Get("groups"), ","),
				"preferred_username": values.Get("username"),
			},
		},
		Headers: &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": cryptutils.KeyID(o.privateKey.PublicKey),
			},
		},
	}
}
