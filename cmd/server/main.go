package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"idp-cyberos/internal/admin"
	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
	"idp-cyberos/internal/handlers"
	"idp-cyberos/internal/saml"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
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

	srv := handlers.NewIdPServer(cfg, kp)
	oidcH := srv.OIDCHandlers()
	adminH := admin.NewHandlers(cfg)

	mux := http.NewServeMux()

	// Static files
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

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

	// Admin console (protected)
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /console", adminH.HandleConsole)
	adminMux.HandleFunc("POST /console/users", adminH.HandleCreateUser)
	adminMux.HandleFunc("GET /console/users", adminH.HandleListUsers)
	mux.Handle("/console", admin.AdminOnly(cfg, adminMux))
	mux.Handle("/console/", admin.AdminOnly(cfg, adminMux))

	log.Printf("IdP server starting on %s (entity: %s)", cfg.ListenAddr, cfg.EntityID)
	log.Printf("Hanko API: %s", cfg.HankoAPIURL)
	if cfg.HankoAdminURL != "" {
		log.Printf("Hanko Admin API: %s", cfg.HankoAdminURL)
	}
	log.Printf("Service Providers (SAML): %d configured", len(cfg.SPs))
	for _, sp := range cfg.SPs {
		log.Printf("  - %s (%s)", sp.Name, sp.EntityID)
	}
	log.Printf("OIDC Clients: %d configured", len(cfg.OIDCClients))
	for _, oc := range cfg.OIDCClients {
		log.Printf("  - %s (client_id: %s)", oc.Name, oc.ClientID)
	}
	log.Printf("Features: public_registration=%v oidc_registration=%v saml_registration=%v admin_emails=%v",
		cfg.Features.AllowPublicRegistration,
		cfg.Features.AllowOIDCRegistration,
		cfg.Features.AllowSAMLRegistration,
		cfg.Features.AdminEmails,
	)

	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
