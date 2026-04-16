package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

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
	ui := authkit.New(authkit.ViewConfig{
		BrandName: "CyberOS SSO",
		BaseURL:   cfg.BaseURL,
		Flow:      creds.FlowConfig(),
		Features: core.FeatureFlags{
			AllowPublicRegistration: cfg.Features.AllowPublicRegistration,
			AllowOIDCRegistration:   cfg.Features.AllowOIDCRegistration,
			AllowSAMLRegistration:   cfg.Features.AllowSAMLRegistration,
		},
		Locales: []string{"en", "ru"},
	})
	srv := server.NewIdPServer(cfg, kp, creds, codeStore, ui)
	oidcH := srv.OIDCHandlers()

	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(authkit.MergedFS(ui.StaticFS(), creds.StaticFS()))))

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
