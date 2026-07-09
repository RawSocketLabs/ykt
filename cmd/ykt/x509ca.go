package main

// Native X.509: the per-domain client CA certificate (CA:TRUE, self-signed
// with the on-device key) and mTLS client certificates from CSRs.
// This replaces the entire OpenSSL/pkcs11-provider/p11tool dance.

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		fatal("entropy failure: %v", err)
	}
	return n
}

// makeClientCACert self-signs the domain client-CA certificate using the
// on-device slot key.
func makeClientCACert(signer crypto.Signer, commonName string) (*x509.Certificate, error) {
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// signClientCert issues a clientAuth certificate from a CSR, signed by the
// domain client CA (key on-device). serial is the ledger-allocated serial,
// used as the X.509 serial number so the cert is trackable in the ledger.
func signClientCert(caCert *x509.Certificate, caSigner crypto.Signer, csrPEM []byte, days int, serial uint64) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetUint64(serial),
		Subject:      csr.Subject,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, csr.PublicKey, caSigner)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// makeCSR builds a CSR for a slot-backed key (used by user-enroll for 9a).
func makeCSR(signer crypto.Signer, commonName string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func loadCertPEM(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func certSHA256Full(cert *x509.Certificate) string {
	sum := sha256Sum(cert.Raw)
	return fmt.Sprintf("SHA256:%x", sum)
}
