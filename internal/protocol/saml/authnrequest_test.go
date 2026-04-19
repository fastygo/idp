package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"idp-cyberos/internal/config"
)

func encodeAuthnRequest(t *testing.T, xml string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write([]byte(xml)); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func newConfigWithSP() *config.Config {
	cfg := &config.Config{
		EntityID: "https://idp.test.local",
		BaseURL:  "https://idp.test.local",
		SPs: []config.ServiceProvider{
			{EntityID: "https://sp.test.local", ACSUrl: "https://sp.test.local/acs", Name: "Test"},
		},
	}
	cfg.BuildIndexes()
	return cfg
}

func TestParseAuthnRequest_AcceptsFresh(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	xml := fmt.Sprintf(`<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_id1" IssueInstant="%s" Destination="https://idp.test.local/sso" AssertionConsumerServiceURL="https://sp.test.local/acs"><saml:Issuer>https://sp.test.local</saml:Issuer></samlp:AuthnRequest>`, now)

	enc := encodeAuthnRequest(t, xml)
	r := httptest.NewRequest("GET", "/sso?SAMLRequest="+url.QueryEscape(enc)+"&RelayState=rs", nil)

	parsed, err := ParseAuthnRequest(r, newConfigWithSP())
	if err != nil {
		t.Fatalf("expected accept, got error: %v", err)
	}
	if parsed.SP.EntityID != "https://sp.test.local" {
		t.Fatalf("SP = %s", parsed.SP.EntityID)
	}
}

func TestParseAuthnRequest_RejectsStaleIssueInstant(t *testing.T) {
	old := time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339)
	xml := fmt.Sprintf(`<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_id1" IssueInstant="%s" AssertionConsumerServiceURL="https://sp.test.local/acs"><saml:Issuer>https://sp.test.local</saml:Issuer></samlp:AuthnRequest>`, old)

	enc := encodeAuthnRequest(t, xml)
	r := httptest.NewRequest("GET", "/sso?SAMLRequest="+url.QueryEscape(enc), nil)

	_, err := ParseAuthnRequest(r, newConfigWithSP())
	if err == nil {
		t.Fatal("expected stale IssueInstant rejection")
	}
	if !strings.Contains(err.Error(), "too old") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseAuthnRequest_RejectsBadDestination(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	xml := fmt.Sprintf(`<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_id1" IssueInstant="%s" Destination="https://attacker.example.com/sso" AssertionConsumerServiceURL="https://sp.test.local/acs"><saml:Issuer>https://sp.test.local</saml:Issuer></samlp:AuthnRequest>`, now)

	enc := encodeAuthnRequest(t, xml)
	r := httptest.NewRequest("GET", "/sso?SAMLRequest="+url.QueryEscape(enc), nil)

	_, err := ParseAuthnRequest(r, newConfigWithSP())
	if err == nil {
		t.Fatal("expected Destination rejection")
	}
	if !strings.Contains(err.Error(), "Destination") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseAuthnRequest_RejectsTooLarge(t *testing.T) {
	// 2 MiB of garbage plus a trailing closing tag — the inflated body
	// is much bigger than maxSAMLRequestSize so the limit must trip.
	pad := strings.Repeat("A", 2*1024*1024)
	xml := `<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_id1"><saml:Issuer>https://sp.test.local</saml:Issuer><!--` + pad + `--></samlp:AuthnRequest>`

	enc := encodeAuthnRequest(t, xml)
	r := httptest.NewRequest("GET", "/sso?SAMLRequest="+url.QueryEscape(enc), nil)

	_, err := ParseAuthnRequest(r, newConfigWithSP())
	if err == nil {
		t.Fatal("expected size rejection")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}
