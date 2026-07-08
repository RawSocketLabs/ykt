// Package ykt embeds the project documentation so the compiled binary can serve
// it offline via `ykt docs` — no network, no external files. The command source
// lives under cmd/ykt/; this root package exists only to embed the Markdown that
// sits alongside it (go:embed cannot reach files outside its own directory).
package ykt

import "embed"

// Docs holds the curated documentation set bundled into the binary and served
// by `ykt docs`. The list is EXPLICIT (not a *.md glob) so a stray root
// Markdown file — internal notes, an AGENTS.md, a scratch TODO — can never be
// silently shipped or served by a security tool. Add new docs here on purpose.
//
//go:embed README.md INSTALL.md RECOVERY.md CONTRIBUTING.md SECURITY.md CODE_OF_CONDUCT.md CHANGELOG.md web/guide.html
var Docs embed.FS

// ConfigExample is the starter config that `ykt repo init` writes into a fresh
// store when none exists yet, so a new operator doesn't have to hunt for it.
//
//go:embed config.toml.example
var ConfigExample []byte
