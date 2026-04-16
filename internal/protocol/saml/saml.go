package saml

import oldsaml "idp-cyberos/internal/saml"

type AuthnRequest = oldsaml.AuthnRequest
type ParsedRequest = oldsaml.ParsedRequest

var (
	ParseAuthnRequest = oldsaml.ParseAuthnRequest
	BuildSAMLResponse = oldsaml.BuildSAMLResponse
	HandleMetadata    = oldsaml.HandleMetadata
)
