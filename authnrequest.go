package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
)

type AuthnRequest struct {
	XMLName xml.Name `xml:"AuthnRequest"`
	ID      string   `xml:"ID,attr"`
	ACSUrl  string   `xml:"AssertionConsumerServiceURL,attr"`
	Issuer  struct {
		Value string `xml:",chardata"`
	} `xml:"Issuer"`
}

type ParsedRequest struct {
	AuthnRequest
	SP         *ServiceProvider
	RelayState string
}

func parseAuthnRequest(r *http.Request, cfg *Config) (*ParsedRequest, error) {
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
	xmlBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("deflate: %w", err)
	}

	var req AuthnRequest
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		return nil, fmt.Errorf("xml parse: %w", err)
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
