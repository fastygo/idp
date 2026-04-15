package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type IdPKeyPair struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
	CertDER     []byte
	CertPEM     string
}

func LoadOrGenerateKeyPair(keyPath, certPath string) (*IdPKeyPair, error) {
	if fileExists(keyPath) && fileExists(certPath) {
		return loadKeyPair(keyPath, certPath)
	}
	return generateAndSaveKeyPair(keyPath, certPath)
}

func loadKeyPair(keyPath, certPath string) (*IdPKeyPair, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	certPEMBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	certBlock, _ := pem.Decode(certPEMBytes)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return &IdPKeyPair{
		PrivateKey:  key,
		Certificate: cert,
		CertDER:     certBlock.Bytes,
		CertPEM:     string(certPEMBytes),
	}, nil
}

func generateAndSaveKeyPair(keyPath, certPath string) (*IdPKeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "CyberOS SSO IdP"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated cert: %w", err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return nil, fmt.Errorf("create key file: %w", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, fmt.Errorf("write key PEM: %w", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return nil, fmt.Errorf("create cert file: %w", err)
	}
	defer certFile.Close()
	certPEMBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	if err := pem.Encode(certFile, certPEMBlock); err != nil {
		return nil, fmt.Errorf("write cert PEM: %w", err)
	}

	certPEM := pem.EncodeToMemory(certPEMBlock)

	return &IdPKeyPair{
		PrivateKey:  key,
		Certificate: cert,
		CertDER:     certDER,
		CertPEM:     string(certPEM),
	}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
