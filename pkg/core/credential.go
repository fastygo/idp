package core

type CredentialVerifier interface {
	VerifyToken(token string) (*IdentityClaims, error)
	FlowConfig() FlowConfig
}
