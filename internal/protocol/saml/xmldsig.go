package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/beevik/etree"

	"idp-cyberos/internal/auth"
)

const (
	nsDS         = "http://www.w3.org/2000/09/xmldsig#"
	nsEC         = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	algRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algC14N      = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

func SignAssertion(doc *etree.Document, kp *auth.IdPKeyPair) error {
	assertion := doc.FindElement("//Assertion")
	if assertion == nil {
		return fmt.Errorf("no Assertion element found")
	}

	assertionID := assertion.SelectAttrValue("ID", "")
	if assertionID == "" {
		return fmt.Errorf("Assertion has no ID attribute")
	}

	digestValue, err := computeDigest(assertion)
	if err != nil {
		return fmt.Errorf("compute digest: %w", err)
	}

	signedInfo := buildSignedInfo(assertionID, digestValue)

	signedInfoC14N, err := canonicalize(signedInfo)
	if err != nil {
		return fmt.Errorf("c14n SignedInfo: %w", err)
	}

	hash := sha256.Sum256([]byte(signedInfoC14N))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, kp.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return fmt.Errorf("RSA sign: %w", err)
	}

	sigEl := buildSignatureElement(signedInfo, sigBytes, kp.CertDER)
	insertAfterIssuer(assertion, sigEl)

	return nil
}

func computeDigest(el *etree.Element) (string, error) {
	c14nBytes, err := canonicalize(el)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(c14nBytes))
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func buildSignedInfo(refID, digestValue string) *etree.Element {
	si := etree.NewElement("ds:SignedInfo")
	si.CreateAttr("xmlns:ds", nsDS)

	cm := si.CreateElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", algC14N)

	sm := si.CreateElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", algRSASHA256)

	ref := si.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "#"+refID)

	transforms := ref.CreateElement("ds:Transforms")

	t1 := transforms.CreateElement("ds:Transform")
	t1.CreateAttr("Algorithm", algEnveloped)

	t2 := transforms.CreateElement("ds:Transform")
	t2.CreateAttr("Algorithm", algC14N)

	dm := ref.CreateElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", algSHA256)

	dv := ref.CreateElement("ds:DigestValue")
	dv.SetText(digestValue)

	return si
}

func buildSignatureElement(signedInfo *etree.Element, sigBytes, certDER []byte) *etree.Element {
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", nsDS)

	sig.AddChild(signedInfo.Copy())

	sv := sig.CreateElement("ds:SignatureValue")
	sv.SetText(base64.StdEncoding.EncodeToString(sigBytes))

	ki := sig.CreateElement("ds:KeyInfo")
	xd := ki.CreateElement("ds:X509Data")
	xc := xd.CreateElement("ds:X509Certificate")
	xc.SetText(base64.StdEncoding.EncodeToString(certDER))

	return sig
}

func insertAfterIssuer(assertion *etree.Element, sig *etree.Element) {
	children := assertion.ChildElements()
	issuerIdx := -1
	for i, ch := range children {
		if ch.Tag == "Issuer" {
			issuerIdx = i
			break
		}
	}

	if issuerIdx == -1 || issuerIdx >= len(children)-1 {
		assertion.AddChild(sig)
		return
	}

	assertion.InsertChild(children[issuerIdx+1], sig)
}

func canonicalize(el *etree.Element) (string, error) {
	var buf strings.Builder
	if err := c14nElement(&buf, el, nil); err != nil {
		return "", err
	}
	return buf.String(), nil
}

type nsEntry struct {
	Prefix string
	URI    string
}

func c14nElement(buf *strings.Builder, el *etree.Element, parentNS []nsEntry) error {
	visibleNS := collectVisibleNS(el, parentNS)

	buf.WriteByte('<')
	if el.Space != "" {
		buf.WriteString(el.Space)
		buf.WriteByte(':')
	}
	buf.WriteString(el.Tag)

	sort.Slice(visibleNS, func(i, j int) bool {
		return visibleNS[i].Prefix < visibleNS[j].Prefix
	})
	for _, ns := range visibleNS {
		buf.WriteByte(' ')
		if ns.Prefix == "" {
			buf.WriteString("xmlns=\"")
		} else {
			buf.WriteString("xmlns:")
			buf.WriteString(ns.Prefix)
			buf.WriteString("=\"")
		}
		buf.WriteString(ns.URI)
		buf.WriteByte('"')
	}

	attrs := make([]etree.Attr, len(el.Attr))
	copy(attrs, el.Attr)
	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].Space == "xmlns" || attrs[i].Key == "xmlns" {
			return false
		}
		if attrs[j].Space == "xmlns" || attrs[j].Key == "xmlns" {
			return false
		}
		if attrs[i].Space != attrs[j].Space {
			return attrs[i].Space < attrs[j].Space
		}
		return attrs[i].Key < attrs[j].Key
	})
	for _, attr := range attrs {
		if attr.Space == "xmlns" || attr.Key == "xmlns" {
			continue
		}
		buf.WriteByte(' ')
		if attr.Space != "" {
			buf.WriteString(attr.Space)
			buf.WriteByte(':')
		}
		buf.WriteString(attr.Key)
		buf.WriteString("=\"")
		buf.WriteString(escapeAttrValue(attr.Value))
		buf.WriteByte('"')
	}

	buf.WriteByte('>')

	mergedNS := mergeNS(parentNS, visibleNS)

	for _, tok := range el.Child {
		switch t := tok.(type) {
		case *etree.Element:
			if err := c14nElement(buf, t, mergedNS); err != nil {
				return err
			}
		case *etree.CharData:
			buf.WriteString(escapeText(t.Data))
		}
	}

	buf.WriteString("</")
	if el.Space != "" {
		buf.WriteString(el.Space)
		buf.WriteByte(':')
	}
	buf.WriteString(el.Tag)
	buf.WriteByte('>')

	return nil
}

func collectVisibleNS(el *etree.Element, parentNS []nsEntry) []nsEntry {
	needed := make(map[string]string)

	if el.Space != "" {
		uri := findNSURI(el, el.Space)
		if uri != "" {
			needed[el.Space] = uri
		}
	} else {
		uri := findDefaultNSURI(el)
		if uri != "" {
			needed[""] = uri
		}
	}

	for _, attr := range el.Attr {
		if attr.Space == "xmlns" || attr.Key == "xmlns" {
			continue
		}
		if attr.Space != "" {
			uri := findNSURI(el, attr.Space)
			if uri != "" {
				needed[attr.Space] = uri
			}
		}
	}

	var result []nsEntry
	for prefix, uri := range needed {
		alreadyDeclared := false
		for _, pns := range parentNS {
			if pns.Prefix == prefix && pns.URI == uri {
				alreadyDeclared = true
				break
			}
		}
		if !alreadyDeclared {
			result = append(result, nsEntry{Prefix: prefix, URI: uri})
		}
	}

	return result
}

func findNSURI(el *etree.Element, prefix string) string {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, attr := range cur.Attr {
			if attr.Space == "xmlns" && attr.Key == prefix {
				return attr.Value
			}
		}
	}
	return ""
}

func findDefaultNSURI(el *etree.Element) string {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, attr := range cur.Attr {
			if attr.Key == "xmlns" && attr.Space == "" {
				return attr.Value
			}
		}
	}
	return ""
}

func mergeNS(parent []nsEntry, added []nsEntry) []nsEntry {
	merged := make([]nsEntry, len(parent))
	copy(merged, parent)
	for _, a := range added {
		found := false
		for i, m := range merged {
			if m.Prefix == a.Prefix {
				merged[i].URI = a.URI
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, a)
		}
	}
	return merged
}

func escapeAttrValue(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "\t", "&#x9;")
	s = strings.ReplaceAll(s, "\n", "&#xA;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}

func escapeText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}
