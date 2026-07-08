package main

// caddy: generate mTLS client-auth config for the Caddy edge, per domain.
// Emits (a) a JSON tls_connection_policies fragment matching the infrax
// config.json style, with the domain's client CA(s) inlined as base64 DER,
// (b) a Caddyfile-style reference snippet, and (c) stages the CA cert files.
// Everything generated is public material.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func cmdCaddy(domains []string, sni string) {
	reg := loadRegistry()
	outDir := trustPath("dist", "caddy")
	if err := ensureDir(outDir); err != nil {
		fatal("%v", err)
	}

	for _, dn := range domains {
		d := reg.domain(dn)

		// collect this domain's client CA cert(s) — one per provisioned anchor
		type caEntry struct {
			anchor, file, b64 string
		}
		var cas []caEntry
		for _, an := range d.AnchorList() {
			path := clientCACertPath(dn, an)
			cert, err := loadCertPEM(path)
			if err != nil {
				continue // anchor not provisioned yet — policy regenerates later
			}
			cas = append(cas, caEntry{an, path, base64.StdEncoding.EncodeToString(cert.Raw)})
		}
		if len(cas) == 0 {
			warn("[%s] no client CA certs published yet — run init ca first; skipping", dn)
			continue
		}

		// Caddy's "*.zone" SNI wildcard matches exactly ONE label, so it
		// covers app.zone but NOT the apex zone nor a.b.zone. Include the apex
		// explicitly and warn about deeper names, so a site is never silently
		// left ungated by falling through to the no-client-auth fallback.
		match := []string{"*." + d.BaseZone(), d.BaseZone()}
		if sni != "" {
			match = cleanPrincipals(sni) // reuse the trim/split helper
		}
		warn("[%s] SNI match = %v. '*.%s' matches ONE label only — multi-level names",
			dn, match, d.BaseZone())
		warn("      (a.b.%s) are NOT gated unless you pass them via --sni.", d.BaseZone())

		// ---- JSON fragment (apps.http.servers.<name>.tls_connection_policies)
		var inline []string
		for _, ca := range cas {
			inline = append(inline, ca.b64)
		}
		policies := []map[string]any{
			{
				"match": map[string]any{"sni": match},
				"client_authentication": map[string]any{
					"mode":             "require_and_verify",
					"trusted_ca_certs": inline,
				},
			},
			// fallback policy: sites not matched above keep working WITHOUT
			// client certs — remove only if the whole server is mTLS-gated
			{},
		}
		buf, err := json.MarshalIndent(map[string]any{"tls_connection_policies": policies}, "", "  ")
		if err != nil {
			fatal("%v", err)
		}
		jsonPath := fmt.Sprintf("%s/%s_mtls.json", outDir, dn)
		act(fmt.Sprintf("[%s] write %s", dn, jsonPath), "", func() error {
			return writeFileAtomic(jsonPath, append(buf, '\n'), 0o644)
		})

		// ---- Caddyfile-style reference
		var cf strings.Builder
		fmt.Fprintf(&cf, "# mTLS gate for the %q domain — Caddyfile reference.\n", dn)
		fmt.Fprintf(&cf, "# Put the tls block inside each site you want gated. CA files land in\n")
		fmt.Fprintf(&cf, "# /etc/caddy/ (staged next to this file). Keep app/API endpoints used by\n")
		fmt.Fprintf(&cf, "# native mobile clients UNGATED (WireGuard-only) — they can't do client certs.\n\n")
		fmt.Fprintf(&cf, "example.%s {\n    tls {\n        client_auth {\n            mode require_and_verify\n", d.BaseZone())
		for _, ca := range cas {
			fmt.Fprintf(&cf, "            trusted_ca_cert_file /etc/caddy/%s_client_ca_%s.crt\n", dn, ca.anchor)
		}
		fmt.Fprintf(&cf, "        }\n    }\n    reverse_proxy upstream:port\n}\n")
		cfPath := fmt.Sprintf("%s/%s_mtls.caddyfile", outDir, dn)
		act(fmt.Sprintf("[%s] write %s", dn, cfPath), "", func() error {
			return writeFileAtomic(cfPath, []byte(cf.String()), 0o644)
		})

		// ---- stage the CA certs for deployment to the edge
		for _, ca := range cas {
			src := ca.file
			dst := fmt.Sprintf("%s/%s_client_ca_%s.crt", outDir, dn, ca.anchor)
			act(fmt.Sprintf("[%s] stage %s", dn, dst), "", func() error {
				return copyFile(src, dst, 0o644)
			})
		}
	}

	head("Caddy config generated → dist/caddy/")
	say("To deploy:")
	say("  1. Copy dist/caddy/*.crt to /etc/caddy/ on the edge host (public material).")
	say("  2. JSON config: merge <domain>_mtls.json's tls_connection_policies into")
	say("     apps.http.servers.<server> — keep the trailing {} fallback policy so")
	say("     un-gated sites keep serving. Narrow the sni match per site as needed")
	say("     (regenerate with --sni host1,host2 for an exact list).")
	say("  3. Caddyfile users: see <domain>_mtls.caddyfile for the per-site block.")
	say("  4. Reload Caddy; a browser with the matching PIV cert gets a picker prompt,")
	say("     anyone without a cert is rejected in the TLS handshake.")
	say("When an anchor is added/re-keyed, re-run this command — the policy embeds")
	say("the CA certs, so it must be regenerated on CA changes.")
}
