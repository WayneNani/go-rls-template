package web

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestIndexGetsAFreshStyleNonce(t *testing.T) {
	index := []byte("<html><head><title>x</title></head><body></body></html>")
	nonceInPage := regexp.MustCompile(`<meta name="csp-nonce" content="([^"]+)" />`)

	seen := map[string]bool{}
	for range 2 {
		rec := httptest.NewRecorder()
		serveIndex(rec, index)
		m := nonceInPage.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("no nonce meta tag in %s", rec.Body.String())
		}
		nonce := m[1]
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "style-src 'self' 'nonce-"+nonce+"';") {
			t.Errorf("CSP does not allow the page's nonce: %s", csp)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", cc)
		}
		if seen[nonce] {
			t.Error("nonce reused across responses")
		}
		seen[nonce] = true
	}
}
