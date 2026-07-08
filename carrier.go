package main

// Route 2 "carry only the YubiKey": OpenSSH keeps the SSH certificate (and the
// FIDO2 key stub) as files, and a YubiKey's PIV applet can only store X.509
// certificate objects — not arbitrary blobs. So we wrap the bytes we want to
// carry inside a throwaway self-signed X.509 certificate, in a private
// extension, and stash that in a spare PIV slot. On another machine `ykt
// hydrate` reads the slot back and re-materializes the file. The carrier's key
// and signature are never validated — the certificate is purely an envelope
// the PIV applet will accept.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// oidYktCarrier is a private-arc OID marking the extension that holds the
// carried bytes. Under a private enterprise arc; never published or validated.
var oidYktCarrier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61234, 7, 1}

// buildCarrier wraps arbitrary payload bytes in a self-signed X.509 certificate
// so a PIV slot's certificate object can hold them. label becomes the subject
// CN purely for human legibility when the slot is inspected.
func buildCarrier(label string, payload []byte) (*x509.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ykt carrier: " + label},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<33, 0), // far future; validity is irrelevant
		ExtraExtensions: []pkix.Extension{{
			Id:    oidYktCarrier,
			Value: payload, // raw bytes; round-trips as the extnValue
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// payloadFromCarrier extracts the bytes a buildCarrier certificate carries.
func payloadFromCarrier(cert *x509.Certificate) ([]byte, error) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidYktCarrier) {
			return e.Value, nil
		}
	}
	return nil, fmt.Errorf("slot certificate is not a ykt carrier (no payload extension)")
}
