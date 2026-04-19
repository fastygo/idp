package server

import (
	"net/http"
	"strings"
	"time"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
	protocoloidc "idp-cyberos/internal/protocol/oidc"
	"idp-cyberos/internal/protocol/saml"
	"idp-cyberos/pkg/authkit"
	"idp-cyberos/pkg/core"
)

type IdPServer struct {
	cfg          *config.Config
	kp           *auth.IdPKeyPair
	creds        core.CredentialVerifier
	codeStore    core.AuthCodeStore
	sessionStore core.SessionStore
	renderer     authkit.Renderer
	oidc         *protocoloidc.Handlers
}

func NewIdPServer(cfg *config.Config, kp *auth.IdPKeyPair, creds core.CredentialVerifier, codeStore core.AuthCodeStore, sessionStore core.SessionStore, revoker core.TokenRevoker, renderer authkit.Renderer) *IdPServer {
	return &IdPServer{
		cfg:          cfg,
		kp:           kp,
		creds:        creds,
		codeStore:    codeStore,
		sessionStore: sessionStore,
		renderer:     renderer,
		oidc:         protocoloidc.NewHandlers(cfg, kp, codeStore, sessionStore, revoker),
	}
}

// SetOIDCHandlers swaps the OIDC handlers attached to this server. The
// production main wiring builds the OIDC handlers with a lifecycle-bound
// background context (so the back-channel logout goroutines can be
// drained on shutdown) and then injects them via this setter.
func (s *IdPServer) SetOIDCHandlers(h *protocoloidc.Handlers) {
	if h == nil {
		return
	}
	s.oidc = h
}

func (s *IdPServer) OIDCHandlers() *protocoloidc.Handlers {
	return s.oidc
}

func (s *IdPServer) ShowLogin(w http.ResponseWriter, r *http.Request) {
	s.renderer.RenderLogin(w, r)
}

func (s *IdPServer) HandleSSO(w http.ResponseWriter, r *http.Request) {
	req, err := saml.ParseAuthnRequest(r, s.cfg)
	if err != nil {
		s.renderer.RenderError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	if sess := auth.GetSession(r, s.cfg.SessionKey); sess != nil {
		s.completeSAML(w, r, req, sess.Email)
		return
	}

	auth.SavePendingRequest(
		w,
		req.ID,
		req.SP.EntityID,
		req.SP.ACSUrl,
		req.RelayState,
		s.cfg.SessionKey,
	)
	s.renderer.RenderLogin(w, r)
}

func (s *IdPServer) HandleSSOComplete(w http.ResponseWriter, r *http.Request) {
	flow := s.creds.FlowConfig()
	token := extractToken(r, flow.CookieName)
	if token == "" {
		s.renderer.RenderError(w, r, "Authentication token not found", http.StatusUnauthorized)
		return
	}

	claims, err := s.creds.VerifyToken(token)
	if err != nil {
		s.renderer.RenderError(w, r, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	sub := claims.Sub
	if sub == "" {
		sub = claims.Email
	}
	sid := auth.GenerateSessionID()
	if s.sessionStore != nil {
		if err := s.sessionStore.Register(&core.SessionRecord{
			SID:       sid,
			Sub:       sub,
			Email:     claims.Email,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(auth.SessionDuration),
		}); err != nil {
			s.renderer.RenderError(w, r, "Failed to register session", http.StatusInternalServerError)
			return
		}
	}
	auth.CreateSession(w, claims.Email, sub, sid, s.cfg.SessionKey)

	// Pick the freshest pending request: an OIDC /authorize started after a
	// stale SAML AuthnRequest must win and vice-versa. Save*PendingRequest
	// already wipes the opposite cookie, so under normal flow only one is
	// present here. We still wipe both at the very end as a defence in
	// depth so no cross-protocol replay is possible on the next visit.
	samlPending := auth.GetPendingRequest(r, s.cfg.SessionKey)
	oidcPending := auth.GetOIDCPendingRequest(r, s.cfg.SessionKey)

	if samlPending != nil {
		sp := s.cfg.FindSP(samlPending.SPEntityID)
		if sp == nil {
			s.renderer.RenderError(w, r, "Unknown service provider", http.StatusBadRequest)
			return
		}

		auth.ClearAllPending(w)
		s.completeSAML(w, r, &saml.ParsedRequest{
			AuthnRequest: saml.AuthnRequest{ID: samlPending.RequestID, ACSUrl: samlPending.ACSUrl},
			SP:           sp,
			RelayState:   samlPending.RelayState,
		}, claims.Email)
		return
	}

	if oidcPending != nil {
		client := s.cfg.FindOIDCClient(oidcPending.ClientID)
		if client == nil {
			s.renderer.RenderError(w, r, "Unknown OIDC client", http.StatusBadRequest)
			return
		}

		auth.ClearAllPending(w)
		s.oidc.IssueCode(w, r, client, oidcPending.RedirectURI, oidcPending.State, oidcPending.Nonce, oidcPending.Scope, claims.Email, sub, sid, oidcPending.CodeChallenge, oidcPending.CodeChallengeMethod)
		return
	}

	auth.ClearAllPending(w)
	http.Redirect(w, r, s.cfg.BaseURL, http.StatusFound)
}

func (s *IdPServer) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.oidc.HandleBrowserLogout(w, r); err != nil {
		s.renderer.RenderError(w, r, "Logout failed", http.StatusInternalServerError)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if !s.cfg.IsAllowedLogoutReturnURL(returnTo) {
		returnTo = s.cfg.DefaultLogoutReturnURL()
	}

	s.renderer.RenderLogout(w, r, returnTo)
}

func (s *IdPServer) completeSAML(w http.ResponseWriter, r *http.Request, req *saml.ParsedRequest, email string) {
	samlResponse, err := saml.BuildSAMLResponse(req, email, s.cfg, s.kp)
	if err != nil {
		s.renderer.RenderError(w, r, "Failed to build SAML response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := saml.RenderPostForm(w, req.SP.ACSUrl, samlResponse, req.RelayState); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

// extractToken pulls the IdP credential JWT from the incoming request.
// Only header- and cookie-based carriers are accepted; query-string tokens
// were removed because URLs land in proxy access logs, browser history and
// Referer headers, which is the exact kind of credential leak we are
// closing as part of the production-hardening pass.
func extractToken(r *http.Request, cookieName string) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return ""
}
