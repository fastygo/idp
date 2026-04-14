package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	applyEnvOverrides(cfg)

	// Ensure keys directory exists
	keysDir := filepath.Dir(cfg.KeyPath)
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		log.Fatalf("Failed to create keys directory: %v", err)
	}

	kp, err := LoadOrGenerateKeyPair(cfg.KeyPath, cfg.CertPath)
	if err != nil {
		log.Fatalf("Failed to load/generate keys: %v", err)
	}
	log.Printf("IdP certificate loaded (subject: %s)", kp.Certificate.Subject.CommonName)

	srv := NewIdPServer(cfg, kp)

	mux := http.NewServeMux()

	// SAML endpoints
	mux.HandleFunc("GET /metadata", handleMetadata(cfg, kp))
	mux.HandleFunc("GET /sso", srv.handleSSO)
	mux.HandleFunc("GET /sso/complete", srv.handleSSOComplete)

	// OIDC endpoints
	mux.HandleFunc("GET /.well-known/openid-configuration", srv.handleOIDCDiscovery)
	mux.HandleFunc("GET /authorize", srv.handleOIDCAuthorize)
	mux.HandleFunc("POST /token", srv.handleOIDCToken)
	mux.HandleFunc("GET /userinfo", srv.handleOIDCUserinfo)
	mux.HandleFunc("GET /jwks", srv.handleOIDCJWKS)

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

	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
