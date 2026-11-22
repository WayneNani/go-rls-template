package auth

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
)

// NewSessions returns the user session and the login transaction.
//
// The user session is SameSite=Strict: it is never sent on a request another site
// starts, so CSRF does not depend on every GET route being free of side effects.
// The SPA's index.html needs no cookie, and its API calls are same-site, so deep
// links from mail or chat still work.
//
// The login transaction (state, nonce, PKCE verifier) is SameSite=Lax because it has
// to survive the IdP's cross-site redirect back to /auth/callback. It lives 10 minutes
// and is deleted after the callback.
func NewSessions(store scs.Store, secure bool) (session, login *scs.SessionManager) {
	session = newManager(store, secure, "session", http.SameSiteStrictMode)
	session.Lifetime = 8 * time.Hour
	session.IdleTimeout = time.Hour

	login = newManager(store, secure, "login", http.SameSiteLaxMode)
	login.Lifetime = 10 * time.Minute
	return session, login
}

func newManager(store scs.Store, secure bool, name string, sameSite http.SameSite) *scs.SessionManager {
	m := scs.New()
	m.Store = store
	m.Cookie.Name = name
	if secure {
		m.Cookie.Name = "__Host-" + name // host-only, Secure, Path=/ enforced by the browser
	}
	m.Cookie.Secure = secure
	m.Cookie.HttpOnly = true
	m.Cookie.Path = "/"
	m.Cookie.SameSite = sameSite
	m.HashTokenInStore = true // a database read does not yield usable session tokens
	return m
}
