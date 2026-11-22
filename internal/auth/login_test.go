package auth

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"example.com/starter/internal/store"
)

func TestReturnPathIsSameOrigin(t *testing.T) {
	for _, p := range []string{"/", "/#access", "/projects?id=1&x=y", "/a/b-c_d.e~f"} {
		if !safeReturn(p) {
			t.Errorf("%q rejected", p)
		}
	}
	for _, p := range []string{
		"", "access", "#access", "https://evil.example/", "//evil.example", "///evil.example",
		"/\\evil.example", "\\/evil.example", "/%2F/evil.example", "/%5Cevil.example",
		"/\t/evil.example", "/\n/evil.example", " /x", "/x y", "javascript:alert(1)",
		"/@evil.example", "/" + string(make([]byte, 200)),
	} {
		if safeReturn(p) {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestAuthTime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   time.Time
	}{
		{"from the IdP", map[string]any{"auth_time": float64(now.Unix() - 3600)}, now.Add(-time.Hour)},
		{"missing: the sign-in is the authentication", map[string]any{}, now},
		{"not a number", map[string]any{"auth_time": "1"}, now},
		{"in the future", map[string]any{"auth_time": float64(now.Unix() + 3600)}, now},
	} {
		if got := authTime(tc.claims, now); !got.Equal(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDisabledUserIsAuditedAsDisabled(t *testing.T) {
	if got := syncFailure(fmt.Errorf("sync: %w", store.ErrUserDisabled)); got != "disabled" {
		t.Errorf("disabled user: %q, want disabled", got)
	}
	if got := syncFailure(errors.New("db down")); got != "user_sync" {
		t.Errorf("other error: %q, want user_sync", got)
	}
}
