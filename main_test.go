package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/beevik/etree"
)

func TestLoadOrGenerateKeyPair(t *testing.T) {
	keyPath := t.TempDir() + "/test.key"
	certPath := t.TempDir() + "/test.crt"

	kp, err := LoadOrGenerateKeyPair(keyPath, certPath)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if kp.Certificate == nil {
		t.Fatal("certificate is nil")
	}
	if len(kp.CertDER) == 0 {
		t.Fatal("cert DER is empty")
	}

	// Reload
	kp2, err := LoadOrGenerateKeyPair(keyPath, certPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if kp2.Certificate.SerialNumber.Cmp(kp.Certificate.SerialNumber) != 0 {
		t.Fatal("serial number changed after reload")
	}
}

func TestMetadataEndpoint(t *testing.T) {
	kp := generateTestKeyPair(t)
	cfg := &Config{
		EntityID: "https://idp.test.local",
		BaseURL:  "https://idp.test.local",
	}

	handler := handleMetadata(cfg, kp)
	req := httptest.NewRequest("GET", "/metadata", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/xml" {
		t.Fatalf("content-type = %s", ct)
	}
	body := rr.Body.String()
	if len(body) < 100 {
		t.Fatal("metadata too short")
	}
}

func TestSignAssertion(t *testing.T) {
	kp := generateTestKeyPair(t)

	cfg := &Config{
		EntityID: "https://idp.test.local",
		BaseURL:  "https://idp.test.local",
		SPs: []ServiceProvider{
			{EntityID: "https://sp.test.local", ACSUrl: "https://sp.test.local/acs", Name: "Test SP"},
		},
	}
	cfg.spIndex = map[string]*ServiceProvider{
		"https://sp.test.local": &cfg.SPs[0],
	}

	req := &ParsedRequest{
		AuthnRequest: AuthnRequest{
			ID: "_test123",
		},
		SP:         &cfg.SPs[0],
		RelayState: "",
	}

	samlB64, err := BuildSAMLResponse(req, "user@test.local", cfg, kp)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}

	xmlBytes, err := base64.StdEncoding.DecodeString(samlB64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}

	// Verify the XML has a Signature element
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("parse xml: %v", err)
	}

	sig := doc.FindElement("//Signature")
	if sig == nil {
		t.Fatal("no Signature element found in SAML Response")
	}

	sv := doc.FindElement("//SignatureValue")
	if sv == nil {
		t.Fatal("no SignatureValue element found")
	}
	if sv.Text() == "" {
		t.Fatal("SignatureValue is empty")
	}

	dv := doc.FindElement("//DigestValue")
	if dv == nil {
		t.Fatal("no DigestValue element found")
	}
	if dv.Text() == "" {
		t.Fatal("DigestValue is empty")
	}

	// Verify assertion has NameID with email
	nameID := doc.FindElement("//NameID")
	if nameID == nil {
		t.Fatal("no NameID found")
	}
	if nameID.Text() != "user@test.local" {
		t.Fatalf("NameID = %q, want user@test.local", nameID.Text())
	}
}

func TestSessionRoundtrip(t *testing.T) {
	key := "test-session-key-1234567890abcde"

	rr := httptest.NewRecorder()
	createSession(rr, "user@test.local", key)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies set")
	}

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	sess := getSession(req, key)
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.Email != "user@test.local" {
		t.Fatalf("email = %q", sess.Email)
	}

	// Wrong key should fail
	sess2 := getSession(req, "wrong-key")
	if sess2 != nil {
		t.Fatal("session should be nil with wrong key")
	}
}

func generateTestKeyPair(t *testing.T) *IdPKeyPair {
	t.Helper()
	dir := t.TempDir()
	kp, err := LoadOrGenerateKeyPair(dir+"/test.key", dir+"/test.crt")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
