package auth

import (
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

	switch client := session.Ar.GetClient().(type) {
	case *DistrustClient:
		log.Debug().Str("client", client.GetID()).Msg("distrust client found, performing additonal validation")
		err := validateGroups(client, values)
		if err != nil {
			log.Warn().Err(err).Msg("group validation failed")
			http.Error(rw, "Access denied", http.StatusForbidden)
			return
		}
	}

	// since scopes do not work with discourse, we simply grant the openid scope
	session.Ar.GrantScope("openid")

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.

	mySessionData := o.newSession(o.issuer, values)
	// H1: bind the audience to this client at the authorize step. The session
	// is persisted and re-loaded on /token, /introspect and /userinfo, so
	// setting it here is sufficient for all downstream code paths.
	mySessionData.Claims.Audience = []string{session.Ar.GetClient().GetID()}
	response, err := o.oauth2.NewAuthorizeResponse(req.Context(), session.Ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Warn().Err(err).Msg("building authorize response")
		o.oauth2.WriteAuthorizeError(ctx, rw, session.Ar, err)
		return
	}

	// Last but not least, send the response!
	o.oauth2.WriteAuthorizeResponse(ctx, rw, session.Ar, response)
}

func (o *OIDCProvider) introspectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	mySessionData := o.newSession(o.issuer, nil)
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
	mySessionData := o.newSession(o.issuer, nil)

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
	session := o.newSession(o.issuer, nil)
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
