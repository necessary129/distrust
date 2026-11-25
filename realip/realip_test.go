package realip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/go-chi/httprate"
)

func mustPrefixes(t *testing.T, entries ...string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(entries)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParsePrefixes(t *testing.T) {
	p := mustPrefixes(t, "10.0.0.0/8", "127.0.0.1", "::1", " 192.168.1.7/24 ")
	want := []string{"10.0.0.0/8", "127.0.0.1/32", "::1/128", "192.168.1.0/24"}
	for i, w := range want {
		if p[i].String() != w {
			t.Errorf("entry %d: got %s want %s", i, p[i], w)
		}
	}
	for _, bad := range []string{"", "not-an-ip", "10.0.0.0/33"} {
		if _, err := ParsePrefixes([]string{bad}); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestMiddlewareRemoteAddr(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8", "fd00::/8")
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"untrusted peer keeps its address", "203.0.113.9:4000", []string{"198.51.100.1"}, "203.0.113.9:4000"},
		{"trusted peer without header", "10.0.0.2:4000", nil, "10.0.0.2:0"},
		{"single proxy", "10.0.0.2:4000", []string{"198.51.100.1"}, "198.51.100.1:0"},
		{"client-injected left entries ignored", "10.0.0.2:4000", []string{"6.6.6.6, 198.51.100.1"}, "198.51.100.1:0"},
		{"chained trusted proxies skipped", "10.0.0.2:4000", []string{"198.51.100.1, 10.0.0.3"}, "198.51.100.1:0"},
		{"multiple header lines", "10.0.0.2:4000", []string{"6.6.6.6", "198.51.100.1, 10.0.0.3"}, "198.51.100.1:0"},
		{"all hops trusted uses leftmost", "10.0.0.2:4000", []string{"10.1.1.1, 10.0.0.3"}, "10.1.1.1:0"},
		{"garbage stops the walk", "10.0.0.2:4000", []string{"198.51.100.1, junk, 10.0.0.3"}, "10.0.0.3:0"},
		{"ipv6 client", "[fd00::1]:4000", []string{"2001:db8::5"}, "[2001:db8::5]:0"},
		{"ipv4-mapped peer", "[::ffff:10.0.0.2]:4000", []string{"198.51.100.1"}, "198.51.100.1:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			h := Middleware(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.RemoteAddr }))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if got != tc.want {
				t.Fatalf("RemoteAddr: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestMiddlewareNoTrustedProxiesIsPassthrough(t *testing.T) {
	var got string
	h := Middleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.RemoteAddr }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:4000"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "10.0.0.2:4000" {
		t.Fatalf("RemoteAddr changed without trusted proxies: %q", got)
	}
}

// Two clients behind the same proxy must get separate per-IP rate-limit
// buckets: exhausting one must not lock out the other.
func TestPerIPRateLimitBehindProxy(t *testing.T) {
	limited := httprate.LimitByIP(2, time.Minute)(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}))
	h := Middleware(mustPrefixes(t, "10.0.0.2"))(limited)

	do := func(client string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:4000"
		req.Header.Set("X-Forwarded-For", client)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	for i := 0; i < 3; i++ {
		do("198.51.100.1")
	}
	if code := do("198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("attacker not limited: %d", code)
	}
	if code := do("198.51.100.2"); code != http.StatusOK {
		t.Fatalf("second client behind the same proxy was limited: %d", code)
	}
}
