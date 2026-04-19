package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
	"idp-cyberos/internal/middleware"
	protocoloidc "idp-cyberos/internal/protocol/oidc"
	"idp-cyberos/internal/protocol/saml"
	"idp-cyberos/internal/server"
	"idp-cyberos/pkg/authkit"
	hanko "idp-cyberos/pkg/authkit-hanko"
	"idp-cyberos/pkg/core"
	"idp-cyberos/pkg/store/memory"
)

// Tunable timeouts for the IdP HTTP listener. The previous setup relied
// on http.ListenAndServe which has *no* timeouts at all, leaving the
// process exposed to slow-loris and idle-connection accumulation. These
// values match the same numbers production audits asked for.
const (
	httpReadHeaderTimeout = 10 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 120 * time.Second

	// Body size caps for the JSON-/form-shaped OIDC endpoints — token,
	// revoke, introspect, end_session. Realistic payloads are well under
	// 8 KiB; capping at 64 KiB keeps a sliver of headroom while making
	// stream-the-body DoS attempts cheap to reject.
	oidcMaxBodyBytes int64 = 64 * 1024

	// Janitor cadence: how often we sweep expired auth codes, sessions
	// and revocations from the in-memory stores. Each sweep is O(n) on
	// the live set; once a minute is enough for a realistic SSO load.
	storeJanitorInterval = 1 * time.Minute

	// Graceful shutdown budget. Long enough to drain in-flight token
	// exchanges and back-channel logout POSTs, short enough not to make
	// container orchestrators give up and SIGKILL the process.
	shutdownTimeout = 25 * time.Second
)

func main() {
	configPath := "config.yaml"

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	config.ApplyEnvOverrides(cfg)

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration is not safe to start: %v", err)
	}

	keysDir := filepath.Dir(cfg.KeyPath)
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		log.Fatalf("Failed to create keys directory: %v", err)
	}

	kp, err := auth.LoadOrGenerateKeyPair(cfg.KeyPath, cfg.CertPath)
	if err != nil {
		log.Fatalf("Failed to load/generate keys: %v", err)
	}
	log.Printf("IdP certificate loaded (subject: %s)", kp.Certificate.Subject.CommonName)

	creds := hanko.NewVerifier(cfg.HankoAPIURL)
	codeStore := memory.NewCodeStore()
	sessionStore := memory.NewSessionStore()
	revoker := memory.NewTokenRevoker()

	// Root context cancelled on SIGINT/SIGTERM. We pass a derived bgCtx
	// to the OIDC handlers so back-channel logout goroutines can be
	// drained on shutdown instead of leaking past process exit.
	rootCtx, cancelRoot := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelRoot()
	var bgWG sync.WaitGroup

	mergedStaticFS := authkit.MergedFS(authkit.UIStaticFS(), creds.StaticFS())
	manifest, err := authkit.BuildManifest(mergedStaticFS)
	if err != nil {
		log.Fatalf("Failed to build static asset manifest: %v", err)
	}
	if err := manifest.Validate(); err != nil {
		log.Fatalf("Static asset manifest invalid: %v", err)
	}

	flow := creds.FlowConfig()
	if e, ok := manifest.LookupLogical(strings.TrimPrefix(flow.SDKScript, "/")); ok {
		flow.SDKScript = "/" + e.FingerprintedPath
		flow.SDKScriptIntegrity = e.IntegritySHA384
		log.Printf("AuthKit bundle: %s (sri=%s, %d bytes plain, %d bytes gzip)",
			flow.SDKScript, flow.SDKScriptIntegrity, len(e.Body()), len(e.Gzipped()))
	} else {
		log.Printf("WARNING: AuthKit bundle %q not found in static manifest; cache and SRI disabled", flow.SDKScript)
	}

	ui := authkit.New(authkit.ViewConfig{
		BrandName: "CyberOS SSO",
		BaseURL:   cfg.BaseURL,
		Flow:      flow,
		Features: core.FeatureFlags{
			AllowPublicRegistration: cfg.Features.AllowPublicRegistration,
			AllowOIDCRegistration:   cfg.Features.AllowOIDCRegistration,
			AllowSAMLRegistration:   cfg.Features.AllowSAMLRegistration,
		},
		Locales: []string{"en", "ru"},
	})
	srv := server.NewIdPServer(cfg, kp, creds, codeStore, sessionStore, revoker, ui)
	oidcH := protocoloidc.NewHandlersWithBackground(cfg, kp, codeStore, sessionStore, revoker, rootCtx, &bgWG)
	srv.SetOIDCHandlers(oidcH)

	mux := http.NewServeMux()

	staticHandler := authkit.FingerprintedHandler(manifest, http.FileServerFS(mergedStaticFS))
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler))
	mux.Handle("HEAD /static/", http.StripPrefix("/static/", staticHandler))

	// Liveness / readiness for orchestrators. Both are intentionally
	// trivial — they just confirm the HTTP server is up and that the
	// signing key has loaded. Heavier checks (e.g. JWKS reachability
	// for the credential verifier) are deliberately *not* part of
	// /healthz so a transient Hanko outage cannot trigger a pod restart
	// loop.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready"))
	})

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cfg.BaseURL, http.StatusFound)
	})

	mux.HandleFunc("GET /metadata", saml.HandleMetadata(cfg, kp))
	mux.HandleFunc("GET /sso", srv.HandleSSO)
	mux.HandleFunc("GET /sso/complete", srv.HandleSSOComplete)
	mux.HandleFunc("GET /logout", srv.HandleLogout)

	mux.HandleFunc("GET /.well-known/openid-configuration", oidcH.HandleDiscovery)
	mux.HandleFunc("GET /authorize", oidcH.HandleAuthorize(srv.ShowLogin))
	mux.HandleFunc("GET /end_session", oidcH.HandleEndSession)
	mux.HandleFunc("POST /end_session", middleware.MaxBodyBytesFunc(oidcMaxBodyBytes, oidcH.HandleEndSession))
	mux.HandleFunc("POST /introspect", middleware.MaxBodyBytesFunc(oidcMaxBodyBytes, oidcH.HandleIntrospect))
	mux.HandleFunc("POST /revoke", middleware.MaxBodyBytesFunc(oidcMaxBodyBytes, oidcH.HandleRevoke))
	mux.HandleFunc("POST /token", middleware.MaxBodyBytesFunc(oidcMaxBodyBytes, oidcH.HandleToken))
	mux.HandleFunc("GET /userinfo", oidcH.HandleUserinfo)
	mux.HandleFunc("GET /jwks", oidcH.HandleJWKS)

	// Run the periodic store janitor for the lifetime of the process.
	// Cleaning the in-memory token revoker, code store and session
	// store is what keeps them from growing unboundedly under sustained
	// traffic — the canonical Go memory-leak shape for long-lived maps.
	go runStoreJanitor(rootCtx, codeStore, sessionStore, revoker)

	log.Printf("IdP server starting on %s (entity: %s)", cfg.ListenAddr, cfg.EntityID)
	log.Printf("Hanko API: %s", cfg.HankoAPIURL)
	log.Printf("Service Providers (SAML): %d configured", len(cfg.SPs))
	for _, sp := range cfg.SPs {
		log.Printf("  - %s (%s)", sp.Name, sp.EntityID)
	}
	log.Printf("OIDC Clients: %d configured", len(cfg.OIDCClients))
	for _, oc := range cfg.OIDCClients {
		log.Printf("  - %s (client_id: %s)", oc.Name, oc.ClientID)
	}
	log.Printf("Features: public_registration=%v oidc_registration=%v saml_registration=%v",
		cfg.Features.AllowPublicRegistration,
		cfg.Features.AllowOIDCRegistration,
		cfg.Features.AllowSAMLRegistration,
	)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           middleware.SecurityHeaders(mux),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		ErrorLog:          log.Default(),
	}

	serverErr := make(chan error, 1)
	go func() {
		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("Server error: %v", err)
		}
	case <-rootCtx.Done():
		log.Printf("Shutdown signal received; draining for up to %s", shutdownTimeout)
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutCtx); err != nil {
			log.Printf("HTTP shutdown error: %v", err)
		}

		// Wait for fire-and-forget goroutines (back-channel logout) to
		// finish, but don't outlast the shutdown budget.
		drained := make(chan struct{})
		go func() {
			bgWG.Wait()
			close(drained)
		}()
		select {
		case <-drained:
		case <-shutCtx.Done():
			log.Printf("Background work did not drain within %s; exiting anyway", shutdownTimeout)
		}
		log.Printf("Server stopped cleanly")
	}
}

// runStoreJanitor periodically calls Cleanup() on each in-memory store.
// In production these are the only thing standing between a long-lived
// IdP process and unbounded map growth (the classic Go memory-leak
// pattern called out in 2025/2026 audits of in-memory token caches).
func runStoreJanitor(ctx context.Context, codeStore core.AuthCodeStore, sessionStore core.SessionStore, revoker core.TokenRevoker) {
	t := time.NewTicker(storeJanitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := codeStore.Cleanup(); err != nil {
				log.Printf("code store cleanup error: %v", err)
			}
			if err := sessionStore.Cleanup(); err != nil {
				log.Printf("session store cleanup error: %v", err)
			}
			if err := revoker.Cleanup(); err != nil {
				log.Printf("token revoker cleanup error: %v", err)
			}
		}
	}
}
