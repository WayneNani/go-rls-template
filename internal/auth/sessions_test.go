package auth_test

import (
	"net/http"
	"testing"
	"time"

	"example.com/starter/internal/auth"
)

func TestSessionCookies(t *testing.T) {
	session, login := auth.NewSessions(nil, true)

	if c := session.Cookie; c.Name != "__Host-session" || c.SameSite != http.SameSiteStrictMode || !c.Secure || !c.HttpOnly {
		t.Errorf("user session cookie must be __Host-, Strict, Secure, HttpOnly: %+v", c)
	}
	if c := login.Cookie; c.Name != "__Host-login" || c.SameSite != http.SameSiteLaxMode || !c.Secure || !c.HttpOnly {
		t.Errorf("login cookie must be __Host-, Lax, Secure, HttpOnly: %+v", c)
	}
	if !session.HashTokenInStore || !login.HashTokenInStore {
		t.Error("session tokens must be stored hashed")
	}
	if login.Lifetime > 10*time.Minute {
		t.Errorf("login transaction lives %v, want at most 10m", login.Lifetime)
	}
}
