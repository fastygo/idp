package core

// FlowConfig describes how the browser-side AuthKit widget reaches the
// authentication backend.
//
// It is produced by a CredentialVerifier (e.g. authkit-hanko) and consumed by
// the renderer (pkg/authkit) to inject the right <script> tag, JSON config
// block and (optionally) Subresource Integrity attributes into the login
// page.
type FlowConfig struct {
	// APIEndpoint is the absolute URL of the auth backend (e.g.
	// "https://api.cybeross.ru"). Used by the JS SDK and to derive an
	// origin for `<link rel="preconnect">`.
	APIEndpoint string
	// CookieName is the name of the auth-backend cookie that holds the
	// access token used by AuthKit's HandleSSOComplete.
	CookieName string
	// LogoutPath is the path on the auth backend that destroys the
	// backend-side session (e.g. "/logout").
	LogoutPath string
	// SDKScript is the URL the browser must load to initialise AuthKit.
	// It may be a fingerprinted path (e.g.
	// "/static/js/authkit-hanko.<hex>.js") so it can be served with
	// long-lived immutable cache headers.
	SDKScript string
	// SDKScriptIntegrity, when non-empty, is the value of the
	// Subresource Integrity attribute that should be applied to both the
	// <script src=SDKScript> tag and the <link rel="preload"> hint. It
	// must follow the spec format: "<algo>-<base64-digest>" (e.g.
	// "sha384-...").
	SDKScriptIntegrity string
	// EndSessionEndpoint is the OIDC RP-initiated logout endpoint hosted
	// by the IdP, surfaced to widgets that drive end_session flows.
	EndSessionEndpoint string
}
