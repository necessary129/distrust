// Package realip resolves the client address of requests that reach distrust
// through trusted reverse proxies.
//
// distrust serves plain HTTP, so production deployments sit behind a
// TLS-terminating proxy and every connection's RemoteAddr is the proxy. Without
// this middleware, per-IP rate limits key on the proxy address and collapse
// into a single bucket shared by every user.
package realip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// ParsePrefixes parses trusted-proxy entries, each either a CIDR
// ("10.0.0.0/8") or a bare address ("127.0.0.1", "::1").
func ParsePrefixes(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", e, err)
			}
			prefixes = append(prefixes, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", e, err)
		}
		a = a.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	return prefixes, nil
}

// Middleware rewrites r.RemoteAddr to the originating client address for
// requests whose immediate peer is a trusted proxy. X-Forwarded-For is walked
// right to left, skipping trusted hops, so entries a client injects at the
// left of the header are never used. Requests from untrusted peers pass
// through unchanged. With no trusted proxies configured the middleware leaves
// every request alone, but logs one warning if it sees X-Forwarded-For, since
// that usually means a proxy is in front and has not been configured.
func Middleware(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(trusted) == 0 {
			var warnOnce sync.Once
			return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Forwarded-For") != "" {
					warnOnce.Do(func() {
						log.Warn().Str("peer", r.RemoteAddr).Msg("request carries X-Forwarded-For but trustedProxies is not configured; " +
							"rate limits will treat all clients behind the proxy as one address")
					})
				}
				next.ServeHTTP(rw, r)
			})
		}
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if ip, ok := clientIP(r, trusted); ok {
				r.RemoteAddr = netip.AddrPortFrom(ip, 0).String()
			}
			next.ServeHTTP(rw, r)
		})
	}
}

// clientIP returns the client address for a request from a trusted peer, or
// false if the peer is not trusted (or RemoteAddr is unparseable).
func clientIP(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	client := peer.Addr().Unmap()
	if !isTrusted(client, trusted) {
		return netip.Addr{}, false
	}

	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// Anything left of an unparseable hop is untrustworthy; settle
			// on the last trusted hop we reached.
			break
		}
		client = a.Unmap()
		if !isTrusted(client, trusted) {
			break
		}
	}
	return client, true
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
