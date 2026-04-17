package core

type TokenRevoker interface {
	Revoke(jti string) error
	IsRevoked(jti string) (bool, error)
	Cleanup() error
}
