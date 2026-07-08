package main

// Native OpenSSH Key Revocation List writer (PROTOCOL.krl format version 1).
// We only need revocation-by-certificate-serial, the simplest section type.
// Verified against `ssh-keygen -Q` during development.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	krlMagic               = 0x5353484b524c0a00 // "SSHKRL\n\0"
	krlFormatVersion       = 1
	krlSectionCertificates = 1
	krlCertSerialList      = 0x20
)

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func putU32(buf []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(buf, v) }
func putU64(buf []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(buf, v) }
func putString(buf []byte, s []byte) []byte {
	buf = putU32(buf, uint32(len(s)))
	return append(buf, s...)
}

// krlCAGroup is one CA's set of revoked certificate serials.
type krlCAGroup struct {
	caPub   []byte // authorized_keys format
	serials []uint64
}

// writeKRL emits a KRL with one certificates-section per CA (certs from a1
// and a2 revoke independently). krlVersion should increase on every
// regeneration so sshd knows it's newer.
func writeKRL(path string, groups []krlCAGroup, krlVersion uint64, comment string) error {
	out, err := buildKRL(groups, krlVersion, comment)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out, 0o644)
}

// buildKRL returns the KRL bytes (one certificates-section per CA). Shared by
// writeKRL (per-domain file) and mergedKRL (a combined KRL for a multi-domain
// host, pushed to sshd's single RevokedKeys file).
func buildKRL(groups []krlCAGroup, krlVersion uint64, comment string) ([]byte, error) {
	var out []byte
	out = putU64(out, krlMagic)
	out = putU32(out, krlFormatVersion)
	out = putU64(out, krlVersion)
	out = putU64(out, uint64(time.Now().Unix()))
	out = putU64(out, 0)      // flags
	out = putString(out, nil) // reserved
	out = putString(out, []byte(comment))

	for _, g := range groups {
		if len(g.serials) == 0 {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(g.caPub)
		if err != nil {
			return nil, fmt.Errorf("parsing CA key: %w", err)
		}
		sort.Slice(g.serials, func(i, j int) bool { return g.serials[i] < g.serials[j] })
		var serialData []byte
		for _, s := range g.serials {
			serialData = putU64(serialData, s)
		}
		var certSection []byte
		certSection = putString(certSection, pub.Marshal()) // CA key blob
		certSection = putString(certSection, nil)           // reserved
		certSection = append(certSection, krlCertSerialList)
		certSection = putString(certSection, serialData)

		out = append(out, krlSectionCertificates)
		out = putString(out, certSection)
	}
	return out, nil
}
