package core

type AuthRequest struct {
	Email    string
	Password string
}

type AuthResult struct {
	UserID        string
	Email         string
	EmailVerified bool
	Token         string
}

type IdentityClaims struct {
	Sub           string
	Email         string
	EmailVerified bool
	Exp           int64
	Issuer        string
}
