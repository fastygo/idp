package handlers

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
	"idp-cyberos/internal/oidc"
	"idp-cyberos/internal/saml"
	"idp-cyberos/internal/web/views"
)

type IdPServer struct {
	cfg       *config.Config
	kp        *auth.IdPKeyPair
	jwt       *auth.JWTVerifier
	oidc      *oidc.Handlers
	codeStore *oidc.CodeStore
	postTpl   *template.Template
}

func NewIdPServer(cfg *config.Config, kp *auth.IdPKeyPair) *IdPServer {
	tplDir := "templates"
	postTpl := template.Must(template.ParseFiles(filepath.Join(tplDir, "postform.html")))

	codeStore := oidc.NewCodeStore()

	return &IdPServer{
		cfg:       cfg,
		kp:        kp,
		jwt:       auth.NewJWTVerifier(cfg.HankoAPIURL),
		oidc:      oidc.NewHandlers(cfg, kp, codeStore),
		codeStore: codeStore,
		postTpl:   postTpl,
	}
}

func (s *IdPServer) OIDCHandlers() *oidc.Handlers {
	return s.oidc
}

func (s *IdPServer) ShowLogin(w http.ResponseWriter, r *http.Request) {
	views.RenderLogin(w, r, s.cfg)
}

func (s *IdPServer) HandleSSO(w http.ResponseWriter, r *http.Request) {
	req, err := saml.ParseAuthnRequest(r, s.cfg)
	if err != nil {
		log.Printf("SSO error: %v", err)
		http.Error(w, "Bad SAML request", http.StatusBadRequest)
		return
	}

	sess := auth.GetSession(r, s.cfg.SessionKey)
	if sess != nil {
		s.issueResponse(w, req, sess.Email)
		return
	}

	auth.SavePendingRequest(w, req.ID, req.SP.EntityID, req.SP.ACSUrl, req.RelayState, s.cfg.SessionKey)
	views.RenderLogin(w, r, s.cfg)
}

func (s *IdPServer) HandleSSOComplete(w http.ResponseWriter, r *http.Request) {
	tokenStr := auth.ExtractHankoToken(r)
	if tokenStr == "" {
		http.Error(w, "Missing authentication", http.StatusUnauthorized)
		return
	}

	claims, err := s.jwt.VerifyToken(tokenStr)
	if err != nil {
		log.Printf("JWT verification failed: %v", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	email := claims.Email.Address
	if email == "" {
		http.Error(w, "No email in token", http.StatusBadRequest)
		return
	}

	auth.CreateSession(w, email, s.cfg.SessionKey)

	oidcPending := auth.GetOIDCPendingRequest(r, s.cfg.SessionKey)
	if oidcPending != nil {
		auth.ClearOIDCPendingRequest(w)
		client := s.cfg.FindOIDCClient(oidcPending.ClientID)
		if client == nil {
			http.Error(w, "Unknown OIDC client", http.StatusBadRequest)
			return
		}
		s.oidc.IssueCode(w, r, client, oidcPending.RedirectURI, oidcPending.State, oidcPending.Nonce, oidcPending.Scope, email)
		return
	}

	pending := auth.GetPendingRequest(r, s.cfg.SessionKey)
	if pending == nil {
		http.Error(w, "No pending authentication request", http.StatusBadRequest)
		return
	}

	sp := s.cfg.FindSP(pending.SPEntityID)
	if sp == nil {
		http.Error(w, "Unknown service provider", http.StatusBadRequest)
		return
	}

	parsedReq := &saml.ParsedRequest{
		AuthnRequest: saml.AuthnRequest{},
		SP:           sp,
		RelayState:   pending.RelayState,
	}
	parsedReq.AuthnRequest.ID = pending.RequestID

	auth.ClearPendingRequest(w)
	s.issueResponse(w, parsedReq, email)
}

func (s *IdPServer) HandleLogout(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if !s.cfg.IsAllowedLogoutReturnURL(returnTo) {
		returnTo = s.cfg.DefaultLogoutReturnURL()
	}

	auth.ClearSession(w)
	auth.ClearPendingRequest(w)
	auth.ClearOIDCPendingRequest(w)

	views.RenderLogout(w, r, s.cfg, returnTo)
}

func (s *IdPServer) issueResponse(w http.ResponseWriter, req *saml.ParsedRequest, email string) {
	samlResp, err := saml.BuildSAMLResponse(req, email, s.cfg, s.kp)
	if err != nil {
		log.Printf("SAML Response build error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	s.postTpl.Execute(w, map[string]string{
		"ACSUrl":       req.SP.ACSUrl,
		"SAMLResponse": samlResp,
		"RelayState":   req.RelayState,
	})
}
