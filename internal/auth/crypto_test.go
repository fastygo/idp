package auth

import (
	"testing"
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

	kp2, err := LoadOrGenerateKeyPair(keyPath, certPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if kp2.Certificate.SerialNumber.Cmp(kp.Certificate.SerialNumber) != 0 {
		t.Fatal("serial number changed after reload")
	}
}
