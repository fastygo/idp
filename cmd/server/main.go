package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
	"idp-cyberos/internal/protocol/saml"
	"idp-cyberos/internal/server"
	"idp-cyberos/pkg/authkit"
	hanko "idp-cyberos/pkg/authkit-hanko"
	"idp-cyberos/pkg/core"
	"idp-cyberos/pkg/store/memory"
)

func main() {
	configPath := "config.yaml"

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	config.ApplyEnvOverrides(cfg)

	keysDir := filepath.Dir(cfg.KeyPath)
	if err := os.MkdirAll(keysDir, 0700); err != nil {
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
	oidcH := srv.OIDCHandlers()

	mux := http.NewServeMux()

	staticHandler := authkit.FingerprintedHandler(manifest, http.FileServerFS(mergedStaticFS))
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler))
	mux.Handle("HEAD /static/", http.StripPrefix("/static/", staticHandler))

	// Root redirect
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cfg.BaseURL, http.StatusFound)
	})

	// SAML endpoints
	mux.HandleFunc("GET /metadata", saml.HandleMetadata(cfg, kp))
	mux.HandleFunc("GET /sso", srv.HandleSSO)
	mux.HandleFunc("GET /sso/complete", srv.HandleSSOComplete)
	mux.HandleFunc("GET /logout", srv.HandleLogout)

	// OIDC endpoints
	mux.HandleFunc("GET /.well-known/openid-configuration", oidcH.HandleDiscovery)
	mux.HandleFunc("GET /authorize", oidcH.HandleAuthorize(srv.ShowLogin))
	mux.HandleFunc("GET /end_session", oidcH.HandleEndSession)
	mux.HandleFunc("POST /end_session", oidcH.HandleEndSession)
	mux.HandleFunc("POST /introspect", oidcH.HandleIntrospect)
	mux.HandleFunc("POST /revoke", oidcH.HandleRevoke)
	mux.HandleFunc("POST /token", oidcH.HandleToken)
	mux.HandleFunc("GET /userinfo", oidcH.HandleUserinfo)
	mux.HandleFunc("GET /jwks", oidcH.HandleJWKS)

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

	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
