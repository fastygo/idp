package hanko

import (
	"strings"

	"idp-cyberos/pkg/core"
)

const defaultCookieName = "hanko"

type Verifier struct {
	jwtVerifier *JWTVerifier
	apiURL      string
}

// VerifierOptions tunes the JWT verifier the Hanko adapter exposes.
// Leaving fields empty preserves the previous behaviour (no iss/aud check).
type VerifierOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
}

func NewVerifier(apiURL string) *Verifier {
	return NewVerifierWithOptions(apiURL, VerifierOptions{})
}

func NewVerifierWithOptions(apiURL string, opts VerifierOptions) *Verifier {
	return &Verifier{
		jwtVerifier: NewJWTVerifierWithOptions(apiURL, JWTVerifierOptions{
			ExpectedIssuer:   opts.ExpectedIssuer,
			ExpectedAudience: opts.ExpectedAudience,
		}),
		apiURL: strings.TrimRight(apiURL, "/"),
	}
}

func (v *Verifier) FlowConfig() core.FlowConfig {
	return core.FlowConfig{
		APIEndpoint:        v.apiURL,
		CookieName:         defaultCookieName,
		LogoutPath:         "/logout",
		SDKScript:          "/static/js/authkit-hanko.js",
		EndSessionEndpoint: "/end_session",
	}
}
