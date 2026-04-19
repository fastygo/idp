package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"idp-cyberos/internal/config"
)

// maxSAMLRequestSize bounds the deflated AuthnRequest XML we are willing
// to parse. SAML AuthnRequests are normally well under 8 KiB; capping at
// 1 MiB avoids billion-XML / zip-bomb style memory exhaustion when a
// malicious SP feeds us a pathologically large blob.
const maxSAMLRequestSize = 1 << 20 // 1 MiB

// authnRequestMaxSkew is how far in the past we accept an AuthnRequest's
// IssueInstant. Anything older than this is treated as a replay or a
// badly clock-skewed SP and rejected.
const authnRequestMaxSkew = 5 * time.Minute

// authnRequestFutureSkew bounds clock-skew tolerance for AuthnRequests
// minted slightly in the future relative to the IdP wall clock.
const authnRequestFutureSkew = 90 * time.Second

type AuthnRequest struct {
	XMLName      xml.Name `xml:"AuthnRequest"`
	ID           string   `xml:"ID,attr"`
	ACSUrl       string   `xml:"AssertionConsumerServiceURL,attr"`
	Destination  string   `xml:"Destination,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Issuer       struct {
		Value string `xml:",chardata"`
	} `xml:"Issuer"`
}

type ParsedRequest struct {
	AuthnRequest
	SP         *config.ServiceProvider
	RelayState string
}

// ParseAuthnRequest decodes, validates and binds the AuthnRequest to a
// configured SP. Validation now covers:
//   - bounded request size (DoS protection)
//   - IssueInstant freshness (anti-replay)
//   - Destination consistency with our /sso endpoint when present
//
// Any of these rejections is reported with a generic "invalid SAML
// request" wrapper to keep the user-facing error page from leaking the
// exact validation rule that fired.
func ParseAuthnRequest(r *http.Request, cfg *config.Config) (*ParsedRequest, error) {
	raw := r.URL.Query().Get("SAMLRequest")
	if raw == "" {
		return nil, fmt.Errorf("missing SAMLRequest parameter")
	}
	relayState := r.URL.Query().Get("RelayState")

	compressed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()
	xmlBytes, err := io.ReadAll(io.LimitReader(reader, maxSAMLRequestSize+1))
	if err != nil {
		return nil, fmt.Errorf("deflate: %w", err)
	}
	if len(xmlBytes) > maxSAMLRequestSize {
		return nil, fmt.Errorf("AuthnRequest exceeds %d bytes", maxSAMLRequestSize)
	}

	var req AuthnRequest
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		return nil, fmt.Errorf("xml parse: %w", err)
	}

	if req.IssueInstant != "" {
		if err := validateIssueInstant(req.IssueInstant, time.Now()); err != nil {
			return nil, err
		}
	}

	if req.Destination != "" && cfg.BaseURL != "" {
		expected := strings.TrimRight(cfg.BaseURL, "/") + "/sso"
		if !destinationMatches(req.Destination, expected) {
			return nil, fmt.Errorf("Destination %q does not match IdP /sso endpoint", req.Destination)
		}
	}

	sp := cfg.FindSP(req.Issuer.Value)
	if sp == nil {
		return nil, fmt.Errorf("unknown SP: %s", req.Issuer.Value)
	}

	return &ParsedRequest{
		AuthnRequest: req,
		SP:           sp,
		RelayState:   relayState,
	}, nil
}

func validateIssueInstant(raw string, now time.Time) error {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		// Fall back to the SAML profile's basic dateTime form which omits
		// fractional seconds.
		t, err = time.Parse("2006-01-02T15:04:05Z", raw)
		if err != nil {
			return fmt.Errorf("invalid IssueInstant %q: %w", raw, err)
		}
	}
	t = t.UTC()
	now = now.UTC()

	if delta := now.Sub(t); delta > authnRequestMaxSkew {
		return fmt.Errorf("AuthnRequest is too old (IssueInstant=%s, now=%s)", t.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if delta := t.Sub(now); delta > authnRequestFutureSkew {
		return fmt.Errorf("AuthnRequest IssueInstant too far in the future (%s)", t.Format(time.RFC3339))
	}
	return nil
}

// destinationMatches accepts trailing-slash variants because some SPs
// emit IdP endpoints with a trailing `/`.
func destinationMatches(actual, expected string) bool {
	a := strings.TrimRight(actual, "/")
	e := strings.TrimRight(expected, "/")
	return strings.EqualFold(a, e)
}
