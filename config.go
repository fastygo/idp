package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// applyEnvOverrides overlays environment variables on top of YAML-loaded config.
// Used for Docker / secrets without committing them to config.yaml.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("IDP_SESSION_KEY"); v != "" {
		cfg.SessionKey = v
	}
	if v := os.Getenv("IDP_ENTITY_ID"); v != "" {
		cfg.EntityID = v
	}
	if v := os.Getenv("IDP_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("IDP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("IDP_HANKO_API_URL"); v != "" {
		cfg.HankoAPIURL = v
	}
	if v := os.Getenv("IDP_KEY_PATH"); v != "" {
		cfg.KeyPath = v
	}
	if v := os.Getenv("IDP_CERT_PATH"); v != "" {
		cfg.CertPath = v
	}

	// Override OIDC client secrets from env (e.g. OIDC_CLIENT_SECRET_MYAPP).
	for i := range cfg.OIDCClients {
		envKey := "OIDC_CLIENT_SECRET_" + strings.ToUpper(cfg.OIDCClients[i].ClientID)
		if v := os.Getenv(envKey); v != "" {
			cfg.OIDCClients[i].ClientSecret = v
		}
		// Rebuild index after override
		cfg.oidcIndex[cfg.OIDCClients[i].ClientID] = &cfg.OIDCClients[i]
	}
}

type ServiceProvider struct {
	EntityID string `yaml:"entity_id"`
	ACSUrl   string `yaml:"acs_url"`
	Name     string `yaml:"name"`
}

type OIDCClient struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
	Name         string   `yaml:"name"`
}

type Config struct {
	EntityID     string            `yaml:"entity_id"`
	BaseURL      string            `yaml:"base_url"`
	ListenAddr   string            `yaml:"listen_addr"`
	HankoAPIURL  string            `yaml:"hanko_api_url"`
	KeyPath      string            `yaml:"key_path"`
	CertPath     string            `yaml:"cert_path"`
	SessionKey   string            `yaml:"session_key"`
	SPs          []ServiceProvider `yaml:"service_providers"`
	OIDCClients  []OIDCClient      `yaml:"oidc_clients"`
	spIndex      map[string]*ServiceProvider
	oidcIndex    map[string]*OIDCClient
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":5800"
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = "keys/idp.key"
	}
	if cfg.CertPath == "" {
		cfg.CertPath = "keys/idp.crt"
	}

	cfg.spIndex = make(map[string]*ServiceProvider, len(cfg.SPs))
	for i := range cfg.SPs {
		cfg.spIndex[cfg.SPs[i].EntityID] = &cfg.SPs[i]
	}

	cfg.oidcIndex = make(map[string]*OIDCClient, len(cfg.OIDCClients))
	for i := range cfg.OIDCClients {
		cfg.oidcIndex[cfg.OIDCClients[i].ClientID] = &cfg.OIDCClients[i]
	}

	return &cfg, nil
}

func (c *Config) FindSP(entityID string) *ServiceProvider {
	return c.spIndex[entityID]
}

func (c *Config) FindOIDCClient(clientID string) *OIDCClient {
	return c.oidcIndex[clientID]
}

func (oc *OIDCClient) ValidRedirectURI(uri string) bool {
	for _, allowed := range oc.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}
