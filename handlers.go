package main

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

type IdPServer struct {
	cfg       *Config
	kp        *IdPKeyPair
	jwt       *JWTVerifier
	codeStore *CodeStore
	loginTpl  *template.Template
	postTpl   *template.Template
}

func NewIdPServer(cfg *Config, kp *IdPKeyPair) *IdPServer {
	tplDir := "templates"
	loginTpl := template.Must(template.ParseFiles(filepath.Join(tplDir, "login.html")))
	postTpl := template.Must(template.ParseFiles(filepath.Join(tplDir, "postform.html")))

	return &IdPServer{
		cfg:       cfg,
		kp:        kp,
		jwt:       NewJWTVerifier(cfg.HankoAPIURL),
		codeStore: NewCodeStore(),
		loginTpl:  loginTpl,
		postTpl:   postTpl,
	}
}

// handleSSO processes the SAML AuthnRequest and either issues a Response
// immediately (if an IdP session exists) or shows the Hanko login form.
func (s *IdPServer) handleSSO(w http.ResponseWriter, r *http.Request) {
	req, err := parseAuthnRequest(r, s.cfg)
	if err != nil {
		log.Printf("SSO error: %v", err)
		http.Error(w, "Bad SAML request", http.StatusBadRequest)
		return
	}

	// Check for existing IdP session
	sess := getSession(r, s.cfg.SessionKey)
	if sess != nil {
		s.issueResponse(w, req, sess.Email)
		return
	}

	// No session — save pending request and show login
	savePendingRequest(w, req, s.cfg.SessionKey)
	s.loginTpl.Execute(w, map[string]string{
		"HankoAPI": s.cfg.HankoAPIURL,
	})
}

// handleSSOComplete is called after Hanko Elements authenticates the user.
// It checks for SAML or OIDC pending request and responds accordingly.
func (s *IdPServer) handleSSOComplete(w http.ResponseWriter, r *http.Request) {
	tokenStr := extractHankoToken(r)
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

	// Create IdP session for cross-protocol SSO
	createSession(w, email, s.cfg.SessionKey)

	// Check for OIDC pending request first
	oidcPending := getOIDCPendingRequest(r, s.cfg.SessionKey)
	if oidcPending != nil {
		clearOIDCPendingRequest(w)
		client := s.cfg.FindOIDCClient(oidcPending.ClientID)
		if client == nil {
			http.Error(w, "Unknown OIDC client", http.StatusBadRequest)
			return
		}
		s.issueOIDCCode(w, r, client, oidcPending.RedirectURI, oidcPending.State, oidcPending.Nonce, oidcPending.Scope, email)
		return
	}

	// Check for SAML pending request
	pending := getPendingRequest(r, s.cfg.SessionKey)
	if pending == nil {
		http.Error(w, "No pending authentication request", http.StatusBadRequest)
		return
	}

	sp := s.cfg.FindSP(pending.SPEntityID)
	if sp == nil {
		http.Error(w, "Unknown service provider", http.StatusBadRequest)
		return
	}

	parsedReq := &ParsedRequest{
		AuthnRequest: AuthnRequest{ID: pending.RequestID},
		SP:           sp,
		RelayState:   pending.RelayState,
	}

	clearPendingRequest(w)
	s.issueResponse(w, parsedReq, email)
}

func (s *IdPServer) issueResponse(w http.ResponseWriter, req *ParsedRequest, email string) {
	samlResp, err := BuildSAMLResponse(req, email, s.cfg, s.kp)
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

func extractHankoToken(r *http.Request) string {
	// Try Authorization header first
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Try hanko cookie
	if cookie, err := r.Cookie("hanko"); err == nil {
		return cookie.Value
	}

	// Try query parameter (for redirect from login page)
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	return ""
}
