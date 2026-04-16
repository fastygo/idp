package hanko

import (
	"strings"

	"idp-cyberos/pkg/provider"
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

func (v *Verifier) FlowConfig() provider.FlowConfig {
	return provider.FlowConfig{
		APIEndpoint: v.apiURL,
		CookieName:  defaultCookieName,
		LogoutPath:  "/logout",
		SDKScript:   "/static/js/hanko-frontend-sdk.js",
		SDKGlobal:   "hankoFrontendSdk",
		SDKClass:    "Hanko",
	}
}
