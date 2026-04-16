package saml

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed postform.html
var postFormFS embed.FS

var postFormTmpl = template.Must(template.ParseFS(postFormFS, "postform.html"))

func RenderPostForm(w http.ResponseWriter, acsURL, samlResponse, relayState string) error {
	var buf bytes.Buffer
	if err := postFormTmpl.Execute(&buf, map[string]string{
		"ACSUrl":       acsURL,
		"SAMLResponse": samlResponse,
		"RelayState":   relayState,
	}); err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write(buf.Bytes())
	return err
}
