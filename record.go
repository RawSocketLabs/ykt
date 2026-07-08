package main

// anchorRecord is the <anchor>.json file written at genesis: serial,
// timestamp, and per-domain CA fingerprints. Deliberately NO PIN/PUK —
// those live on paper (or in Vaultwarden), never on disk.

import (
	"encoding/json"
	"os"
	"strconv"
	"time"
)

type anchorRecord struct {
	Serial    uint32                       `json:"serial"`
	Timestamp int64                        `json:"timestamp"`
	Domains   map[string]map[string]string `json:"domains"`
}

func (r anchorRecord) write(path string) error {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(buf, '\n'), 0o644)
}

func nowUnix() int64 { return time.Now().Unix() }

// buildAnchorRecord assembles the record from published pub/ material.
func buildAnchorRecord(reg *Registry, anchorName string, serial uint32) anchorRecord {
	rec := anchorRecord{Serial: serial, Timestamp: nowUnix(), Domains: map[string]map[string]string{}}
	for _, dn := range reg.domainsOn(anchorName) {
		entry := map[string]string{}
		for _, role := range []string{"user", "host"} {
			if b, err := os.ReadFile(caPubPath(dn, role, anchorName)); err == nil {
				entry[role] = sshFingerprint(b)
			} else {
				warn("[%s] %s CA pub for anchor %q missing — fingerprint checklist will be INCOMPLETE (pull the full repo)", dn, role, anchorName)
			}
		}
		if cert, err := loadCertPEM(clientCACertPath(dn, anchorName)); err == nil {
			entry["tls"] = certSHA256Full(cert)
		} else {
			warn("[%s] client CA cert for anchor %q missing — TLS fingerprint absent from checklist", dn, anchorName)
		}
		rec.Domains[dn] = entry
	}
	return rec
}

// cmdDataRecord regenerates <anchor>.json from the published trust material —
// useful if genesis was interrupted or the file was lost.
func cmdDataRecord(args []string) {
	if len(args) != 1 {
		fatal("usage: ykt data record <a1|a2>")
	}
	reg := loadRegistry()
	anchorName := args[0]
	anchor := reg.anchor(anchorName)
	var serial uint32
	if n, err := parseUint32(anchor.YubikeySerial); err == nil {
		serial = n
	}
	rec := buildAnchorRecord(reg, anchorName, serial)
	if len(rec.Domains) == 0 {
		fatal("no published CA material for anchor %q in pub/", anchorName)
	}
	path := trustPath(anchorName + ".json")
	if dryRun {
		note("dry-run: %s not written", path)
	} else if err := rec.write(path); err != nil {
		fatal("%v", err)
	} else {
		good("wrote %s", path)
	}
	for _, dn := range sortedKeys(rec.Domains) {
		for _, role := range []string{"user", "host", "tls"} {
			if fp, ok := rec.Domains[dn][role]; ok {
				say("  %-5s %-5s %s", dn, role, fp)
			}
		}
	}
}

func parseUint32(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}
