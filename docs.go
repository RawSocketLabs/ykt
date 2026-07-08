// Package ykt embeds the project documentation so the compiled binary can serve
// it offline via `ykt docs` — no network, no external files. The command source
// lives under cmd/ykt/; this root package exists only to embed the Markdown that
// sits alongside it (go:embed cannot reach files outside its own directory).
package ykt

import "embed"

// Docs holds every Markdown document at the repo root plus the illustrated
// getting-started guide (web/guide.html), bundled into the binary.
//
//go:embed *.md web/guide.html
var Docs embed.FS
