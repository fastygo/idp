package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

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

type Features struct {
	AllowPublicRegistration bool     `yaml:"allow_public_registration"`
	AllowOIDCRegistration   bool     `yaml:"allow_oidc_registration"`
	AllowSAMLRegistration   bool     `yaml:"allow_saml_registration"`
	AdminEmails             []string `yaml:"admin_emails"`
}

type SMTPConfig struct {
	Host        string `yaml:"host"`
	Port        string `yaml:"port"`
	FromAddress string `yaml:"from_address"`
	FromName    string `yaml:"from_name"`
	User        string `yaml:"user"`
	Password    string `yaml:"password"`
}

type Config struct {
	EntityID      string            `yaml:"entity_id"`
	BaseURL       string            `yaml:"base_url"`
	ListenAddr    string            `yaml:"listen_addr"`
	HankoAPIURL   string            `yaml:"hanko_api_url"`
	KeyPath       string            `yaml:"key_path"`
	CertPath      string            `yaml:"cert_path"`
	SessionKey    string            `yaml:"session_key"`
	SPs           []ServiceProvider `yaml:"service_providers"`
	OIDCClients   []OIDCClient      `yaml:"oidc_clients"`
	Features      Features          `yaml:"features"`
	HankoAdminURL string            `yaml:"hanko_admin_url"`
	SMTP          SMTPConfig        `yaml:"smtp"`
	spIndex       map[string]*ServiceProvider
	oidcIndex     map[string]*OIDCClient
}

func Load(path string) (*Config, error) {
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

func ApplyEnvOverrides(cfg *Config) {
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
	if v := os.Getenv("IDP_HANKO_ADMIN_URL"); v != "" {
		cfg.HankoAdminURL = v
	}
	if v := os.Getenv("IDP_KEY_PATH"); v != "" {
		cfg.KeyPath = v
	}
	if v := os.Getenv("IDP_CERT_PATH"); v != "" {
		cfg.CertPath = v
	}

	if v := os.Getenv("SMTP_HOST"); v != "" {
		cfg.SMTP.Host = v
	}
	if v := os.Getenv("SMTP_PORT"); v != "" {
		cfg.SMTP.Port = v
	}
	if v := os.Getenv("SMTP_USER"); v != "" {
		cfg.SMTP.User = v
	}
	if v := os.Getenv("SMTP_PASSWORD"); v != "" {
		cfg.SMTP.Password = v
	}
	if v := os.Getenv("SMTP_FROM_ADDRESS"); v != "" {
		cfg.SMTP.FromAddress = v
	}
	if v := os.Getenv("SMTP_FROM_NAME"); v != "" {
		cfg.SMTP.FromName = v
	}

	for i := range cfg.OIDCClients {
		envKey := "OIDC_CLIENT_SECRET_" + strings.ToUpper(cfg.OIDCClients[i].ClientID)
		if v := os.Getenv(envKey); v != "" {
			cfg.OIDCClients[i].ClientSecret = v
		}
		cfg.oidcIndex[cfg.OIDCClients[i].ClientID] = &cfg.OIDCClients[i]
	}
}

func (c *Config) BuildIndexes() {
	c.spIndex = make(map[string]*ServiceProvider, len(c.SPs))
	for i := range c.SPs {
		c.spIndex[c.SPs[i].EntityID] = &c.SPs[i]
	}
	c.oidcIndex = make(map[string]*OIDCClient, len(c.OIDCClients))
	for i := range c.OIDCClients {
		c.oidcIndex[c.OIDCClients[i].ClientID] = &c.OIDCClients[i]
	}
}

func (c *Config) FindSP(entityID string) *ServiceProvider {
	return c.spIndex[entityID]
}

func (c *Config) FindOIDCClient(clientID string) *OIDCClient {
	return c.oidcIndex[clientID]
}

func (c *Config) IsAdmin(email string) bool {
	for _, admin := range c.Features.AdminEmails {
		if strings.EqualFold(admin, email) {
			return true
		}
	}
	return false
}

func (c *Config) DefaultLogoutReturnURL() string {
	if len(c.SPs) > 0 {
		return ensureTrailingSlash(c.SPs[0].EntityID)
	}
	for _, client := range c.OIDCClients {
		if len(client.RedirectURIs) > 0 {
			if origin := originOf(client.RedirectURIs[0]); origin != "" {
				return origin + "/"
			}
		}
	}
	return ensureTrailingSlash(c.BaseURL)
}

func (c *Config) IsAllowedLogoutReturnURL(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "/") {
		return true
	}

	target, err := url.Parse(raw)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return false
	}

	allowedOrigins := map[string]struct{}{}
	if origin := originOf(c.BaseURL); origin != "" {
		allowedOrigins[origin] = struct{}{}
	}
	for _, sp := range c.SPs {
		if origin := originOf(sp.EntityID); origin != "" {
			allowedOrigins[origin] = struct{}{}
		}
	}
	for _, client := range c.OIDCClients {
		for _, redirectURI := range client.RedirectURIs {
			if origin := originOf(redirectURI); origin != "" {
				allowedOrigins[origin] = struct{}{}
			}
		}
	}

	_, ok := allowedOrigins[target.Scheme+"://"+target.Host]
	return ok
}

func (oc *OIDCClient) ValidRedirectURI(uri string) bool {
	for _, allowed := range oc.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func ensureTrailingSlash(raw string) string {
	if raw == "" {
		return raw
	}
	return strings.TrimRight(raw, "/") + "/"
}
