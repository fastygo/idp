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

func NewVerifier(apiURL string) *Verifier {
	return &Verifier{
		jwtVerifier: NewJWTVerifier(apiURL),
		apiURL:      strings.TrimRight(apiURL, "/"),
	}
}

func (v *Verifier) FlowConfig() core.FlowConfig {
	return core.FlowConfig{
		APIEndpoint: v.apiURL,
		CookieName:  defaultCookieName,
		LogoutPath:  "/logout",
		SDKScript:   "/static/js/authkit-hanko.js",
	}
}
