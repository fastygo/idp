package saml

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/beevik/etree"

	"idp-cyberos/internal/auth"
	"idp-cyberos/internal/config"
)

const (
	nsSAML  = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsSAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
)

func BuildSAMLResponse(req *ParsedRequest, email string, cfg *config.Config, kp *auth.IdPKeyPair) (string, error) {
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notOnOrAfter := now.Add(5 * time.Minute)
	sessionExpiry := now.Add(8 * time.Hour)
	ts := func(t time.Time) string { return t.Format("2006-01-02T15:04:05Z") }

	responseID := "_resp_" + generateID()
	assertionID := "_assert_" + generateID()
	sessionIndex := "_sess_" + generateID()

	doc := etree.NewDocument()

	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsSAMLP)
	resp.CreateAttr("xmlns:saml", nsSAML)
	resp.CreateAttr("ID", responseID)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", ts(now))
	resp.CreateAttr("Destination", req.SP.ACSUrl)
	resp.CreateAttr("InResponseTo", req.ID)

	issuer := resp.CreateElement("saml:Issuer")
	issuer.SetText(cfg.EntityID)

	status := resp.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	assertion := resp.CreateElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", nsSAML)
	assertion.CreateAttr("ID", assertionID)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", ts(now))

	aIssuer := assertion.CreateElement("saml:Issuer")
	aIssuer.SetText(cfg.EntityID)

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nameID.SetText(email)

	subjectConf := subject.CreateElement("saml:SubjectConfirmation")
	subjectConf.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjectConfData := subjectConf.CreateElement("saml:SubjectConfirmationData")
	subjectConfData.CreateAttr("InResponseTo", req.ID)
	subjectConfData.CreateAttr("Recipient", req.SP.ACSUrl)
	subjectConfData.CreateAttr("NotOnOrAfter", ts(notOnOrAfter))

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", ts(notBefore))
	conditions.CreateAttr("NotOnOrAfter", ts(notOnOrAfter))
	audienceRestriction := conditions.CreateElement("saml:AudienceRestriction")
	audience := audienceRestriction.CreateElement("saml:Audience")
	audience.SetText(req.SP.EntityID)

	authnStmt := assertion.CreateElement("saml:AuthnStatement")
	authnStmt.CreateAttr("AuthnInstant", ts(now))
	authnStmt.CreateAttr("SessionIndex", sessionIndex)
	authnStmt.CreateAttr("SessionNotOnOrAfter", ts(sessionExpiry))
	authnCtx := authnStmt.CreateElement("saml:AuthnContext")
	authnCtxRef := authnCtx.CreateElement("saml:AuthnContextClassRef")
	authnCtxRef.SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	attrStmt := assertion.CreateElement("saml:AttributeStatement")
	attr := attrStmt.CreateElement("saml:Attribute")
	attr.CreateAttr("Name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	attr.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
	attrVal := attr.CreateElement("saml:AttributeValue")
	attrVal.SetText(email)

	if err := SignAssertion(doc, kp); err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}

	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("serialize XML: %w", err)
	}

	return base64.StdEncoding.EncodeToString(xmlBytes), nil
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	return fmt.Sprintf("%x", b)
}
