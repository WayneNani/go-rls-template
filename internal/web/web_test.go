package web_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"example.com/starter/internal/web"
)

func TestContentSecurityPolicy(t *testing.T) {
	rec := httptest.NewRecorder()
	web.SecurityHeaders(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	csp := rec.Header().Get("Content-Security-Policy")

	for _, want := range []string{
		"script-src 'self';",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"require-trusted-types-for 'script'",
		"trusted-types default",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	for _, banned := range []string{"unsafe-inline", "unsafe-eval", "'allow-duplicates'", "*"} {
		if strings.Contains(csp, banned) {
			t.Errorf("CSP contains %q: %s", banned, csp)
		}
	}
}
