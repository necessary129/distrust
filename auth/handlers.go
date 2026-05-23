package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/parkour-vienna/distrust/discourse"
	"github.com/rs/zerolog/log"
)

func (o *OIDCProvider) authEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := o.oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Warn().Err(err).Msg("parsing authorize request")
		o.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	// OIDC `prompt=none` forbids any user-visible interaction. Discourse's
	// SSO provider has no quiet-failure mode, so a bounce to Discourse can
	// surface its login UI and violate the spec. Honour it locally: if we
	// have a recent LoginSession for this browser we replay it; otherwise
	// we redirect back to the RP with error=login_required immediately.
	if hasPromptNone(ar) {
		o.handlePromptNone(ctx, rw, req, ar)
		return
	}

	callback := o.issuer + "/callback"
	nonce, err := discourse.NewNonce()
	if err != nil {
		log.Error().Err(err).Msg("generating nonce")
		http.Error(rw, "failed to initialize login", http.StatusInternalServerError)
		return
	}
	url := discourse.GenerateURL(o.discourseServer, callback, o.discourseSecret, nonce)

	sessionId := uuid.New()
	expiration := time.Now().Add(time.Minute * 10)

	log.Debug().Str("sessionId", sessionId.String()).Msg("registering in flight request")
	o.storeInFlight(sessionId, &InFlightRequest{
		Nonce:     nonce,
		ExpiresAt: expiration,
		Ar:        ar,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     "oidc_session",
		Value:    sessionId.String(),
		Path:     o.root,
		Expires:  expiration,
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   o.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(rw, req, url, http.StatusTemporaryRedirect)
}

func (o *OIDCProvider) callbackEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	log.Trace().Msg("got a discourse callback")
	cookie, err := req.Cookie("oidc_session")
	if err != nil {
		log.Warn().Err(err).Msg("fetching cookie")
		writeInvalidSession(rw, http.StatusBadRequest)
		return
	}
	sessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		writeInvalidSession(rw, http.StatusBadRequest)
		return
	}

	session, ok := o.popInFlight(sessionID)
	if !ok {
		writeInvalidSession(rw, http.StatusUnauthorized)
		return
	}
	if time.Now().After(session.ExpiresAt) {
		writeInvalidSession(rw, http.StatusUnauthorized)
		return
	}

	values, err := discourse.ValidateResponse(req.URL.Query().Get("sso"), req.URL.Query().Get("sig"), o.discourseSecret, session.Nonce)
	if err != nil {
		o.oauth2.WriteAuthorizeError(ctx, rw, session.Ar, err)
		return
	}

	if err := validateDiscoursePayload(values); err != nil {
		log.Warn().Err(err).Msg("rejecting discourse payload")
		o.oauth2.WriteAuthorizeError(ctx, rw, session.Ar, err)
		return
	}

	log.Debug().
		Str("username", values.Get("username")).
		Str("groups", values.Get("groups")).
		Msg("parsed user data")

	// Pin authTime to a single instant so the LoginSession, the cookie,
	// and the id_token's auth_time claim all agree.
	authTime := time.Now()

	// Issue the long-lived login session before WriteAuthorizeResponse so a
	// subsequent silent /auth?prompt=none can replay it. If cookie write
	// fails the silent path simply won't be available; the interactive
	// flow is still complete.
	o.issueLoginCookie(rw, authTime, values)

	o.completeAuthorize(ctx, rw, session.Ar, values, authTime)
}

// hasPromptNone reports whether the OIDC `prompt` parameter contained
// the `none` token. fosite validates that `none` is not combined with
// other prompt values at request creation time, so a presence check is
// sufficient here.
func hasPromptNone(ar fosite.AuthorizeRequester) bool {
	for _, p := range strings.Fields(ar.GetRequestForm().Get("prompt")) {
		if p == "none" {
			return true
		}
	}
	return false
}

// handlePromptNone services the silent-authentication branch of /auth.
// If a valid LoginSession is bound to the browser, we replay the cached
// Discourse identity through fosite without ever bouncing to Discourse.
// Otherwise we send the RP an `error=login_required` redirect, per OIDC
// Core §3.1.2.6.
func (o *OIDCProvider) handlePromptNone(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar fosite.AuthorizeRequester) {
	loginSession, ok := o.lookupLoginSessionFromRequest(req)
	if !ok {
		log.Debug().Msg("prompt=none without active login session, returning login_required")
		o.oauth2.WriteAuthorizeError(ctx, rw, ar, fosite.ErrLoginRequired)
		return
	}

	if err := validateDiscoursePayload(loginSession.Values); err != nil {
		// The cached payload was validated when it was stored; this would
		// only fail if the validation rules tightened across a restart, in
		// which case forcing a fresh login is the correct outcome.
		log.Warn().Err(err).Msg("cached login session payload no longer valid, returning login_required")
		o.oauth2.WriteAuthorizeError(ctx, rw, ar, fosite.ErrLoginRequired)
		return
	}

	o.completeAuthorize(ctx, rw, ar, loginSession.Values, loginSession.AuthTime)
}

// completeAuthorize finalises an authorize request once a Discourse
// identity is available. Shared by /callback (fresh login) and the
// prompt=none silent path on /auth. authTime is the moment the user
// actually authenticated against Discourse and feeds the `auth_time`
// claim plus fosite's prompt/max_age validation.
func (o *OIDCProvider) completeAuthorize(ctx context.Context, rw http.ResponseWriter, ar fosite.AuthorizeRequester, values url.Values, authTime time.Time) {
	switch client := ar.GetClient().(type) {
	case *DistrustClient:
		log.Debug().Str("client", client.GetID()).Msg("distrust client found, performing additonal validation")
		if err := validateGroups(client, values); err != nil {
			log.Warn().Err(err).Msg("group validation failed")
			http.Error(rw, "Access denied", http.StatusForbidden)
			return
		}
	}

	// since scopes do not work with discourse, we simply grant the openid scope
	ar.GrantScope("openid")

	mySessionData := o.newSession(o.issuer, values, authTime)
	// H1: bind the audience to this client at the authorize step. The session
	// is persisted and re-loaded on /token, /introspect and /userinfo, so
	// setting it here is sufficient for all downstream code paths.
	mySessionData.Claims.Audience = []string{ar.GetClient().GetID()}
	response, err := o.oauth2.NewAuthorizeResponse(ctx, ar, mySessionData)
	if err != nil {
		log.Warn().Err(err).Msg("building authorize response")
		o.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	o.oauth2.WriteAuthorizeResponse(ctx, rw, ar, response)
}

// issueLoginCookie records a fresh LoginSession server-side and binds
// the browser to it with the distrust_login cookie. Called from
// /callback once the Discourse response is verified.
func (o *OIDCProvider) issueLoginCookie(rw http.ResponseWriter, authTime time.Time, values url.Values) {
	id := uuid.New()
	expires := authTime.Add(loginSessionTTL)
	o.storeLoginSession(id, &LoginSession{
		AuthTime:  authTime,
		ExpiresAt: expires,
		Values:    values,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     loginCookieName,
		Value:    id.String(),
		Path:     o.root,
		Expires:  expires,
		MaxAge:   int(loginSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   o.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// lookupLoginSessionFromRequest resolves the distrust_login cookie to a
// live LoginSession, returning (nil, false) for any unparseable, unknown
// or expired identifier so callers can fold all failures into a single
// `login_required` response.
func (o *OIDCProvider) lookupLoginSessionFromRequest(req *http.Request) (*LoginSession, bool) {
	cookie, err := req.Cookie(loginCookieName)
	if err != nil {
		return nil, false
	}
	id, err := uuid.Parse(cookie.Value)
	if err != nil {
		return nil, false
	}
	return o.lookupLoginSession(id)
}

func (o *OIDCProvider) introspectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	mySessionData := o.newSession(o.issuer, nil, time.Time{})
	ir, err := o.oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		log.Warn().Err(err).Msg("introspection request failed")
		o.oauth2.WriteIntrospectionError(ctx, rw, err)
		return
	}

	o.oauth2.WriteIntrospectionResponse(ctx, rw, ir)
}

func (o *OIDCProvider) revokeEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	// This will accept the token revocation request and validate various parameters.
	err := o.oauth2.NewRevocationRequest(ctx, req)

	// All done, send the response.
	o.oauth2.WriteRevocationResponse(ctx, rw, err)
}

func (o *OIDCProvider) tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	// Create an empty session object which will be passed to the request handlers
	mySessionData := o.newSession(o.issuer, nil, time.Time{})

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := o.oauth2.NewAccessRequest(ctx, req, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Warn().Err(err).Msg("parsing access request")
		o.oauth2.WriteAccessError(ctx, rw, accessRequest, err)
		return
	}

	// If this is a client_credentials grant, grant all requested scopes
	// NewAccessRequest validated that all requested scopes the client is allowed to perform
	// based on configured scope matching strategy.
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range accessRequest.GetRequestedScopes() {
			accessRequest.GrantScope(scope)
		}
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := o.oauth2.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.Warn().Err(err).Msg("building access response")
		o.oauth2.WriteAccessError(ctx, rw, accessRequest, err)
		return
	}

	log.Info().Str("username", accessRequest.GetSession().(*openid.DefaultSession).Claims.Subject).Msg("user successfully authenticated")

	// All done, send the response.
	o.oauth2.WriteAccessResponse(ctx, rw, accessRequest, response)

	// The client now has a valid access token
}

func (o *OIDCProvider) informationEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(o.discoveryJSON)
}

func (o *OIDCProvider) certsEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(o.jwksJSON)
}

func (o *OIDCProvider) userInfoEndpoint(rw http.ResponseWriter, req *http.Request) {
	session := o.newSession(o.issuer, nil, time.Time{})
	tokenType, ar, err := o.oauth2.IntrospectToken(req.Context(), fosite.AccessTokenFromRequest(req), fosite.AccessToken, session)
	if err != nil {
		rfcerr := fosite.ErrorToRFC6749Error(err)
		if rfcerr.StatusCode() == http.StatusUnauthorized {
			setBearerErrorHeader(rw, rfcerr.ErrorField)
		}
		log.Warn().Err(err).Msg("userinfo introspect failed")
		http.Error(rw, "invalid access token", http.StatusUnauthorized)
		return
	}

	if tokenType != fosite.AccessToken {
		setBearerErrorHeader(rw, "invalid_token")
		http.Error(rw, "invalid access token", http.StatusUnauthorized)
		return
	}

	info := ar.GetSession().(*openid.DefaultSession).Claims.ToMap()
	delete(info, "rat")
	delete(info, "exp")
	delete(info, "at_hash")
	_ = json.NewEncoder(rw).Encode(info)
}

// maxClaimFieldBytes bounds the per-field length of values copied from a
// Discourse SSO payload into ID-token claims. The HMAC verifies integrity but
// not shape; this caps the blast radius of a hostile or buggy upstream.
const maxClaimFieldBytes = 256

// validateDiscoursePayload enforces basic shape constraints on the post-HMAC
// SSO payload before its fields are copied into ID-token claims (M8).
func validateDiscoursePayload(v url.Values) error {
	required := []string{"external_id", "username"}
	for _, k := range required {
		if v.Get(k) == "" {
			return fmt.Errorf("discourse payload missing required field %q", k)
		}
	}
	if _, err := strconv.ParseInt(v.Get("external_id"), 10, 64); err != nil {
		return fmt.Errorf("discourse external_id is not numeric: %w", err)
	}
	bounded := []string{"external_id", "username", "name", "email", "avatar_url", "groups"}
	for _, k := range bounded {
		if len(v.Get(k)) > maxClaimFieldBytes {
			return fmt.Errorf("discourse payload field %q exceeds %d bytes", k, maxClaimFieldBytes)
		}
	}
	if email := v.Get("email"); email != "" {
		if _, err := mail.ParseAddress(email); err != nil {
			return fmt.Errorf("discourse payload email is malformed: %w", err)
		}
	}
	return nil
}

// writeInvalidSession writes a JSON error body for the OIDC callback session
// failures and sets a real HTTP status (vs. the implicit 200 OK that an
// unconditional Encoder.Encode produces).
func writeInvalidSession(rw http.ResponseWriter, status int) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid session, please try again"})
}

// setBearerErrorHeader writes an RFC 6750 §3-compliant WWW-Authenticate header.
// errField is restricted to the OAuth2 error-code charset so we can safely
// inline it without quoting risk.
func setBearerErrorHeader(rw http.ResponseWriter, errField string) {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			return r
		}
		return -1
	}, errField)
	if safe == "" {
		safe = "invalid_token"
	}
	rw.Header().Set("WWW-Authenticate", `Bearer realm="oauth2", error="`+safe+`"`)
}

func validateGroups(client *DistrustClient, values url.Values) error {
	groupMap := make(map[string]bool)
	for _, g := range splitGroups(values.Get("groups")) {
		groupMap[g] = true
	}
	for _, allowed := range client.AllowGroups {
		if groupMap[allowed] {
			return nil
		}
	}
	if len(client.AllowGroups) != 0 {
		return errors.New("user is not in allowed groups for this client")
	}
	for _, denied := range client.DenyGroups {
		if groupMap[denied] {
			return errors.New("access is denied for user in group " + denied)
		}
	}
	return nil
}
