package auth

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/rs/zerolog/log"
)

// clientAuthGuard throttles callers that keep failing client authentication
// on the endpoints that verify a client secret (/token, /introspect,
// /revoke). Every wrong secret costs a full bcrypt comparison (~0.25s of CPU
// at cost 12), and client IDs are public, so without this guard a handful of
// unauthenticated requests per second can keep a core busy. Only failures
// (HTTP 401) are counted, so a correctly configured relying party is never
// throttled no matter how many tokens it requests.
type clientAuthGuard struct {
	limiter     *httprate.RateLimiter
	maxFailures int
	window      time.Duration
}

func newClientAuthGuard(maxFailures int, window time.Duration) *clientAuthGuard {
	return &clientAuthGuard{
		limiter:     httprate.NewRateLimiter(maxFailures, window),
		maxFailures: maxFailures,
		window:      window,
	}
}

// wrap rejects requests from an address that is over its failure budget
// before the handler (and therefore bcrypt) runs, and charges the address
// for each 401 the handler produces. A nil guard is a no-op.
func (g *clientAuthGuard) wrap(h http.HandlerFunc) http.HandlerFunc {
	if g == nil {
		return h
	}
	return func(rw http.ResponseWriter, req *http.Request) {
		key, _ := httprate.KeyByIP(req)
		// Status' own verdict only trips once the count is above the limit;
		// compare the (sliding-window) rate so exactly maxFailures are allowed.
		if _, failures, err := g.limiter.Status(key); err == nil && failures >= float64(g.maxFailures) {
			log.Warn().Str("from", key).Str("path", req.URL.Path).Msg("too many failed client authentications, rejecting")
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Retry-After", strconv.Itoa(int(g.window.Seconds())))
			rw.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(rw).Encode(map[string]string{
				"error":             "temporarily_unavailable",
				"error_description": "too many failed client authentication attempts, try again later",
			})
			return
		}

		ww := middleware.NewWrapResponseWriter(rw, req.ProtoMajor)
		h(ww, req)
		if ww.Status() == http.StatusUnauthorized {
			_ = g.limiter.Counter().Increment(key, time.Now().UTC().Truncate(g.window))
		}
	}
}
