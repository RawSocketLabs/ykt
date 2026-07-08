package main

// docs: serve the bundled Markdown documentation as a small local web page and
// open it in a browser. Fully offline — the docs are embedded in the binary and
// rendered server-side; no network, no external assets.

import (
	"bytes"
	"fmt"
	"html"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	ykt "github.com/RawSocketLabs/ykt"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

func cmdDocs(port int, noBrowser bool) {
	md := goldmark.New(goldmark.WithExtensions(extension.GFM))

	pages, err := fs.Glob(ykt.Docs, "*.md")
	if err != nil || len(pages) == 0 {
		fatal("no documentation is bundled in this build")
	}
	sort.Slice(pages, func(i, j int) bool { return docRank(pages[i]) < docRank(pages[j]) })

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" || name == "index.html" {
			http.Redirect(w, r, "/README.md", http.StatusFound)
			return
		}
		src, err := ykt.Docs.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var body bytes.Buffer
		if err := md.Convert(src, &body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(docPage(name, pages, body.String())))
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fatal("cannot start the docs server: %v", err)
	}
	url := "http://" + ln.Addr().String() + "/README.md"

	head("ykt docs")
	say("Serving the bundled documentation at:")
	say("  %s", url)
	say("Press Ctrl-C to stop.")
	if !noBrowser {
		if err := openBrowser(url); err != nil {
			note("couldn't launch a browser automatically — open the URL above.")
		}
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.Serve(ln); err != nil {
		fatal("docs server: %v", err)
	}
}

// docRank orders the nav: README first, the how-to docs next, the rest after.
func docRank(name string) int {
	for i, n := range []string{
		"README.md", "INSTALL.md", "RECOVERY.md", "README-RSL.md",
		"CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
	} {
		if name == n {
			return i
		}
	}
	return 100
}

// docTitle turns a filename into a nav label.
func docTitle(name string) string {
	switch name {
	case "README.md":
		return "Overview"
	case "README-RSL.md":
		return "RSL notes"
	}
	return strings.TrimSuffix(name, ".md")
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func docPage(active string, pages []string, bodyHTML string) string {
	var nav strings.Builder
	for _, p := range pages {
		cls := ""
		if p == active {
			cls = ` class="active"`
		}
		fmt.Fprintf(&nav, `<a href="/%s"%s>%s</a>`, html.EscapeString(p), cls, html.EscapeString(docTitle(p)))
	}
	return fmt.Sprintf(docTemplate, html.EscapeString(docTitle(active)), nav.String(), bodyHTML)
}

const docTemplate = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%[1]s · ykt docs</title>
<style>
  :root{--bg:#f1f4f1;--surface:#fafcf9;--ink:#1b211d;--muted:#5b685f;--line:#d5ddd5;
    --brass:#8a6c1f;--teal:#2c665e;--code:#e7ede7;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
    --serif:"Charter","Bitstream Charter","Iowan Old Style",Georgia,serif;}
  @media (prefers-color-scheme:dark){:root{--bg:#141815;--surface:#1b211d;--ink:#dde3dd;
    --muted:#91a096;--line:#2c352e;--brass:#cba64b;--teal:#6cbcb0;--code:#101512;}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--serif);
    line-height:1.6;display:flex;min-height:100vh}
  nav{width:220px;flex:none;background:var(--surface);border-right:1px solid var(--line);
    padding:1.4rem 1rem;position:sticky;top:0;height:100vh;overflow:auto}
  nav .brand{font-family:var(--mono);font-weight:700;font-size:1.1rem;color:var(--brass);
    letter-spacing:.02em;margin:0 0 1.2rem;padding-left:.4rem}
  nav a{display:block;font-family:var(--mono);font-size:.82rem;color:var(--muted);
    text-decoration:none;padding:.4rem .5rem;border-radius:6px;margin-bottom:.15rem}
  nav a:hover{background:var(--code);color:var(--ink)}
  nav a.active{background:color-mix(in srgb,var(--brass) 16%%,transparent);color:var(--ink);font-weight:700}
  main{flex:1;min-width:0;padding:2.5rem 3rem;max-width:60rem}
  main h1,main h2,main h3{font-family:var(--mono);line-height:1.25;text-wrap:balance}
  main h1{font-size:1.8rem;border-bottom:2px solid var(--ink);padding-bottom:.4rem}
  main h2{font-size:1.3rem;margin-top:2.2rem}
  main a{color:var(--teal)}
  main code{font-family:var(--mono);font-size:.85em;background:var(--code);padding:.12em .35em;border-radius:4px}
  main pre{background:var(--code);padding:1rem;border-radius:8px;overflow-x:auto}
  main pre code{background:none;padding:0}
  main table{border-collapse:collapse;display:block;overflow-x:auto}
  main th,main td{border:1px solid var(--line);padding:.45rem .7rem;text-align:left}
  main th{font-family:var(--mono);font-size:.8rem;background:var(--surface)}
  main blockquote{border-left:3px solid var(--brass);margin:1rem 0;padding:.3rem 1rem;color:var(--muted)}
  main img{max-width:100%%}
  @media(max-width:720px){body{flex-direction:column}nav{width:auto;height:auto;position:static;border-right:none;border-bottom:1px solid var(--line)}main{padding:1.5rem}}
</style></head>
<body>
<nav><p class="brand">🔑 ykt</p>%[2]s</nav>
<main>%[3]s</main>
</body></html>`
