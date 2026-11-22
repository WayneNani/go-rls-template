// Package web serves the built SPA and sets the security headers for every response.
package web

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// cspFor returns the Content-Security-Policy: no inline scripts, no eval, no third-party
// origins. Inline <style> tags only with the per-response nonce (index.html carries it for
// the components that inject styles, see frontend/src/csp-nonce.ts); other responses get
// no nonce at all. Trusted Types are enforced with a single policy named "default"
// (frontend/src/trusted-types.ts, an exact allowlist), and no other policy may be created.
// The page reports violations to /csp-report (frontend/src/csp-report.ts).
func cspFor(nonce string) string {
	style := "style-src 'self'"
	if nonce != "" {
		style += " 'nonce-" + nonce + "'"
	}
	return "default-src 'self'; script-src 'self'; " + style + "; img-src 'self'; font-src 'self'; " +
		"connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; " +
		"require-trusted-types-for 'script'; trusted-types default"
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspFor(""))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// CSPReport logs the CSP and Trusted Types violations the page reports (POST /csp-report).
// The route is rate limited per IP (cmd/server); the body is capped here.
func CSPReport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err == nil && len(body) > 0 {
		slog.WarnContext(r.Context(), "csp violation", "report", string(body))
	}
	w.WriteHeader(http.StatusNoContent)
}

// SPA serves the files in dist. Every other path is a client-side route and gets
// index.html, rendered per request with a fresh CSP nonce.
func SPA() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // the embed pattern guarantees the directory
	}
	files := http.FileServerFS(sub)
	index, _ := fs.ReadFile(sub, "index.html") // empty before the first `make web`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "index.html" {
			if info, err := fs.Stat(sub, p); err == nil && !info.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // hashed file names
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, index)
	})
}

func serveIndex(w http.ResponseWriter, index []byte) {
	nonce := newNonce()
	meta := []byte(`<meta name="csp-nonce" content="` + nonce + `" />`)
	page := bytes.Replace(index, []byte("</head>"), append(meta, []byte("</head>")...), 1)
	h := w.Header()
	h.Set("Content-Security-Policy", cspFor(nonce))
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store") // a nonce must never be reused from a cache
	_, _ = w.Write(page)
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails (crypto/rand panics instead since Go 1.24)
	return base64.StdEncoding.EncodeToString(b)
}
