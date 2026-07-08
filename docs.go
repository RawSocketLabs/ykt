// Package ykt embeds the project documentation so the compiled binary can serve
// it offline via `ykt docs` — no network, no external files. The command source
// lives under cmd/ykt/; this root package exists only to embed the Markdown that
// sits alongside it (go:embed cannot reach files outside its own directory).
package ykt

import "embed"

// Docs holds every Markdown document at the repo root, bundled into the binary.
//
//go:embed *.md
var Docs embed.FS
