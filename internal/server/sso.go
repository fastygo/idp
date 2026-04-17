package server

import (
	"net/http"
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

	if pending := auth.GetPendingRequest(r, s.cfg.SessionKey); pending != nil {
		sp := s.cfg.FindSP(pending.SPEntityID)
		if sp == nil {
			s.renderer.RenderError(w, r, "Unknown service provider", http.StatusBadRequest)
			return
		}

		auth.ClearPendingRequest(w)
		s.completeSAML(w, r, &saml.ParsedRequest{
			AuthnRequest: saml.AuthnRequest{ID: pending.RequestID, ACSUrl: pending.ACSUrl},
			SP:           sp,
			RelayState:   pending.RelayState,
		}, claims.Email)
		return
	}

	if pending := auth.GetOIDCPendingRequest(r, s.cfg.SessionKey); pending != nil {
		client := s.cfg.FindOIDCClient(pending.ClientID)
		if client == nil {
			s.renderer.RenderError(w, r, "Unknown OIDC client", http.StatusBadRequest)
			return
		}

		auth.ClearOIDCPendingRequest(w)
		s.oidc.IssueCode(w, r, client, pending.RedirectURI, pending.State, pending.Nonce, pending.Scope, claims.Email, sub, sid, pending.CodeChallenge, pending.CodeChallengeMethod)
		return
	}

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

func extractToken(r *http.Request, cookieName string) string {
	if authHeader := r.Header.Get("Authorization"); len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return r.URL.Query().Get("token")
}
