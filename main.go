package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/ory/fosite"
	"github.com/parkour-vienna/distrust/auth"
	"github.com/parkour-vienna/distrust/discourse"
	"github.com/parkour-vienna/distrust/requestlog"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

type clientConfig struct {
	// Secret is a plaintext secret that will be bcrypted at startup. Mutually
	// exclusive with SecretHash.
	Secret string
	// SecretHash is a pre-bcrypted secret. Use this when the operator does not
	// want plaintext secrets in the config file. Mutually exclusive with Secret.
	SecretHash   string
	RedirectURIs []string
	AllowGroups  []string
	DenyGroups   []string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		genkey()
		return
	}

	viper.SetConfigName("distrust")
	viper.AddConfigPath("/etc/distrust")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println(err)
		fmt.Printf("failed to load config file.\n" +
			"A config file is required to run distrust. It should be located in `/etc/distrust` or the current working directory\n")
		os.Exit(1)
	}
	viper.SetEnvPrefix("distrust")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	lvl, err := zerolog.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		log.Fatal().Str("level", viper.GetString("log.level")).Msg("invalid log level")
	}
	zerolog.SetGlobalLevel(lvl)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("goos", runtime.GOOS).Str("goarch", runtime.GOARCH).Msg("runtime environment")

	dsettings := discourse.SSOConfig{
		Server: viper.GetString("discourse.server"),
		Secret: viper.GetString("discourse.secret"),
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(securityHeaders)
	r.Use(requestlog.Zerologger)
	r.Get("/", func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, dsettings.Server, http.StatusTemporaryRedirect)
	})

	// oauth2 setup
	issuer := viper.GetString("oidc.issuer")
	if issuer == "" {
		log.Fatal().Msg("oidc.issuer is required (set it to the public base URL of the /oauth2 path of this server)")
	}

	rawKey := viper.GetString("oidc.privatekey")
	if rawKey == "" {
		log.Fatal().Msg("oidc.privatekey is required; generate one with `distrust genkey`")
	}
	priv, err := parsePrivateKey(rawKey)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load oidc.privatekey")
	}

	secret := viper.GetString("oidc.secret")
	if len(secret) != 32 {
		log.Fatal().Int("len", len(secret)).Msg("oidc.secret must be exactly 32 bytes long")
	}

	clients := map[string]clientConfig{}
	if err := viper.UnmarshalKey("clients", &clients); err != nil {
		log.Fatal().Err(err).Msg("failed to parse clients")
	}
	fclients, err := toFositeClients(clients)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid client configuration")
	}
	log.Info().Int("numClients", len(fclients)).Msg("clients loaded")

	oidc, err := auth.NewOIDC("/oauth2", dsettings, fclients,
		auth.WithIssuer(issuer),
		auth.WithPrivateKey(priv),
		auth.WithSecret([]byte(secret)),
		// Per-IP rate limiter on the user-initiated discourse handshake.
		// 30 attempts per minute is generous enough not to bother real users
		// (each /auth → /callback round-trip uses two requests) but cuts off
		// brute-force enumeration of nonces or session IDs.
		auth.WithAuthRateLimiter(httprate.LimitByIP(30, time.Minute)),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to construct OIDC provider")
	}
	r.Route("/oauth2", oidc.RegisterHandlers)

	srv := &http.Server{
		Addr:              viper.GetString("listenAddr"),
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info().Str("url", "http://"+viper.GetString("listenAddr")).Msg("Starting server")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("http server failed")
		}
	}()

	<-ctx.Done()
	log.Info().Msg("shutdown signal received, draining connections")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn().Err(err).Msg("http server shutdown reported an error")
	}
	if err := oidc.Shutdown(shutdownCtx); err != nil {
		log.Warn().Err(err).Msg("oidc provider shutdown reported an error")
	}
	log.Info().Msg("shutdown complete")
}

// securityHeaders sets baseline response headers that are sound defaults for an
// API/OIDC server: tell browsers not to MIME-sniff, never frame the responses,
// and (when running on https) require HTTPS for a year. CSP is intentionally
// strict — distrust serves no HTML in normal flows.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		h := rw.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if req.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(rw, req)
	})
}

func toFositeClients(clients map[string]clientConfig) (map[string]fosite.Client, error) {
	r := make(map[string]fosite.Client)
	for k, v := range clients {
		if len(v.RedirectURIs) == 0 {
			return nil, fmt.Errorf("client %q: redirectURIs must not be empty", k)
		}

		hasSecret := v.Secret != ""
		hasHash := v.SecretHash != ""
		if hasSecret == hasHash {
			return nil, fmt.Errorf("client %q: exactly one of `secret` or `secretHash` must be set", k)
		}

		var hs []byte
		if hasHash {
			hs = []byte(v.SecretHash)
			if _, err := bcrypt.Cost(hs); err != nil {
				return nil, fmt.Errorf("client %q: secretHash is not a valid bcrypt hash: %w", k, err)
			}
		} else {
			h, err := bcrypt.GenerateFromPassword([]byte(v.Secret), 12)
			if err != nil {
				return nil, fmt.Errorf("client %q: failed to bcrypt secret: %w", k, err)
			}
			hs = h
		}

		r[k] = &auth.DistrustClient{
			DefaultClient: fosite.DefaultClient{
				ID:            k,
				Secret:        hs,
				RedirectURIs:  v.RedirectURIs,
				ResponseTypes: []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "client_credentials"},
				Scopes:        []string{"openid", "profile", "email"},
			},
			AllowGroups: v.AllowGroups,
			DenyGroups:  v.DenyGroups,
		}
		if len(v.AllowGroups) != 0 && len(v.DenyGroups) != 0 {
			log.Warn().Str("client", k).Msg("allow and deny group options are set. allow groups will be used")
		}
	}
	return r, nil
}

func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("no pem block found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return key, nil
}
