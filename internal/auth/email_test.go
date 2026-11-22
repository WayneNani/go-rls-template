package auth

import "testing"

func TestOnlyVerifiedEmailsAreStored(t *testing.T) {
	strict, trusting := &Auth{}, &Auth{cfg: Config{TrustEmail: true}}
	for _, tc := range []struct {
		name   string
		claims map[string]any
		a      *Auth
		want   bool
	}{
		{"verified", map[string]any{"email": "a@x", "email_verified": true}, strict, true},
		{"unverified", map[string]any{"email": "a@x", "email_verified": false}, strict, false},
		{"claim missing", map[string]any{"email": "a@x"}, strict, false},
		{"claim as string is not proof", map[string]any{"email": "a@x", "email_verified": "true"}, strict, false},
		{"trusted IdP", map[string]any{"email": "a@x"}, trusting, true},
	} {
		if got := tc.a.verifiedEmail(tc.claims) != nil; got != tc.want {
			t.Errorf("%s: stored = %v, want %v", tc.name, got, tc.want)
		}
	}
}
