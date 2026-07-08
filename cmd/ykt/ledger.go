package main

// The issued-certificate ledger: one TSV per domain in index/, format-
// compatible with the bash reference implementation.
// columns: serial  type  identity  principals  anchor  signed  expires  file

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type LedgerEntry struct {
	Serial     uint64 // per-domain block serial; also the X.509 serial for TLS certs
	Type       string // user | host | tls
	Identity   string
	Principals string
	Anchor     string
	Signed     string // YYYY-MM-DD
	Expires    string // YYYY-MM-DD
	File       string
	Revoked    bool
}

func ledgerPath(domain string) string { return trustPath("index", domain+".tsv") }

// ledgerWarned suppresses repeat anomaly warnings for the same domain within one
// process (loadLedger is called many times per command).
var ledgerWarned = map[string]bool{}

func loadLedger(domain string) []LedgerEntry {
	raw, err := os.ReadFile(ledgerPath(domain))
	if err != nil {
		return nil
	}
	var out []LedgerEntry
	seen := map[uint64]bool{}
	var anomalies []string
	for i, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			anomalies = append(anomalies, fmt.Sprintf("line %d: only %d fields", i+1, len(f)))
			continue
		}
		e := LedgerEntry{Type: f[1], Identity: f[2], Principals: f[3],
			Anchor: f[4], Signed: f[5], Expires: f[6], File: f[7]}
		if f[0] != "-" { // "-" is an intentional no-serial (legacy) row
			n, perr := strconv.ParseUint(f[0], 10, 64)
			switch {
			case perr != nil:
				anomalies = append(anomalies, fmt.Sprintf("line %d: unparseable serial %q", i+1, f[0]))
			case seen[n]:
				anomalies = append(anomalies, fmt.Sprintf("line %d: duplicate serial %d", i+1, n))
				e.Serial = n
			default:
				e.Serial = n
				seen[n] = true
			}
		}
		if len(f) >= 9 && f[8] == "REVOKED" {
			e.Revoked = true
		}
		out = append(out, e)
	}
	if len(anomalies) > 0 && !ledgerWarned[domain] {
		ledgerWarned[domain] = true
		warn("ledger index/%s.tsv has anomalies (serial-reuse risk) — %s", domain, strings.Join(anomalies, "; "))
	}
	return out
}

// appendLedger appends a row atomically (read → append → temp+rename), so a
// crash mid-write can't leave a truncated final row that loadLedger would skip —
// which would let the next issuance reuse that serial.
func appendLedger(domain string, e LedgerEntry) error {
	if err := os.MkdirAll(trustPath("index"), 0o755); err != nil {
		return err
	}
	path := ledgerPath(domain)
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var b strings.Builder
	if len(existing) == 0 {
		b.WriteString("#serial\ttype\tidentity\tprincipals\tanchor\tsigned\texpires\tfile\n")
	} else {
		b.Write(existing)
		if existing[len(existing)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	serial := "-"
	if e.Serial != 0 {
		serial = strconv.FormatUint(e.Serial, 10)
	}
	fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		serial, e.Type, e.Identity, e.Principals, e.Anchor, e.Signed, e.Expires, e.File)
	return writeFileAtomic(path, []byte(b.String()), 0o644)
}

// markRevoked marks every given serial's row REVOKED in one read+write pass.
// Serials already revoked are treated as no-ops (idempotent); serials with no
// matching row are returned so the caller can decide whether that is fatal.
// Returns the serials that were newly marked and the ones not found.
func markRevoked(domain string, serials []uint64) (marked, notFound []uint64, err error) {
	raw, rerr := os.ReadFile(ledgerPath(domain))
	if rerr != nil {
		return nil, nil, rerr
	}
	lines := strings.Split(string(raw), "\n")
	changed := false
	for _, serial := range serials {
		prefix := strconv.FormatUint(serial, 10) + "\t"
		hit := false
		for i, line := range lines {
			if strings.HasPrefix(line, prefix) {
				hit = true
				if !strings.HasSuffix(line, "\tREVOKED") {
					lines[i] = line + "\tREVOKED"
					changed = true
					marked = append(marked, serial)
				}
			}
		}
		if !hit {
			notFound = append(notFound, serial)
		}
	}
	if changed && !dryRun {
		if werr := writeFileAtomic(ledgerPath(domain), []byte(strings.Join(lines, "\n")), 0o644); werr != nil {
			return marked, notFound, werr
		}
	}
	return marked, notFound, nil
}

// appendLedgerOnce is appendLedger guarded by the SERIAL, so a retry after a
// mid-step failure does not create a duplicate row (same serial → skip), while
// a renewal — same person+host+file but a NEW serial — IS recorded. Dedup by
// File would wrongly skip renewals. Every cert (incl. TLS) now carries a
// unique block serial, so this is uniform. Honors dry-run.
func appendLedgerOnce(domain string, e LedgerEntry) error {
	if dryRun {
		return nil
	}
	if e.Serial == 0 {
		return fmt.Errorf("internal: ledger entry for %s has no serial", e.File)
	}
	for _, existing := range loadLedger(domain) {
		if existing.Serial == e.Serial {
			return nil // already recorded (a retry of the same signing)
		}
	}
	return appendLedger(domain, e)
}

// moveToDone moves a queue file into queue/<domain>/done/, treating an
// already-moved file (source gone, dest present) as success so retries work.
func moveToDone(qfile, domain string) error {
	if dryRun {
		return nil
	}
	doneDir := trustPath("queue", domain, "done")
	if err := os.MkdirAll(doneDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(doneDir, filepath.Base(qfile))
	if err := os.Rename(qfile, dst); err != nil {
		if os.IsNotExist(err) {
			if _, derr := os.Stat(dst); derr == nil {
				return nil // already moved on a prior attempt
			}
		}
		return err
	}
	return nil
}

// nextSerial allocates within the anchor's 1000-block, past anything issued.
// The block runs [SerialBase+1 .. SerialBase+999]; if it is exhausted this
// fatals rather than silently colliding into the next anchor's block.
func nextSerial(domain string, anchor Anchor) uint64 {
	max := anchor.SerialBase
	for _, e := range loadLedger(domain) {
		if e.Serial > anchor.SerialBase && e.Serial <= anchor.SerialBase+999 && e.Serial > max {
			max = e.Serial
		}
	}
	if max >= anchor.SerialBase+999 {
		fatal("serial block for this domain/anchor (%d..%d) is exhausted — widen serial_base spacing in config.toml", anchor.SerialBase+1, anchor.SerialBase+999)
	}
	return max + 1
}

func expiryFromValidity(v string) string {
	span, err := parseValidity(v)
	if err != nil {
		return "?"
	}
	return time.Now().Add(span).Format("2006-01-02")
}

func today() string { return time.Now().Format("2006-01-02") }
