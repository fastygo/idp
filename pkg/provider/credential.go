package provider

import "idp-cyberos/pkg/core"

type CredentialVerifier interface {
	VerifyToken(token string) (*core.IdentityClaims, error)
	FlowConfig() FlowConfig
}

type FlowConfig struct {
	APIEndpoint string
	CookieName  string
	LogoutPath  string
	SDKScript   string
	SDKGlobal   string
	SDKClass    string
}
