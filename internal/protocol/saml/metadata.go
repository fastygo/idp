package saml

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
)

const metadataTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="%s"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor
      WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="%s/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func HandleMetadata(cfg *config.Config, kp *auth.IdPKeyPair) http.HandlerFunc {
	certB64 := base64.StdEncoding.EncodeToString(kp.CertDER)
	body := fmt.Sprintf(metadataTemplate, cfg.EntityID, certB64, cfg.BaseURL)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(body))
	}
}
