// Package auth signs users in through any OIDC provider (authorization code + PKCE)
// and keeps them in a server-side session. It is the only package that reads ID
// token claims (depguard), so no handler can decide on a raw claim.
package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"example.com/starter/internal/authz"
	"example.com/starter/internal/ratelimit"
	"example.com/starter/internal/store"
	"example.com/starter/internal/store/db"
	"example.com/starter/internal/telemetry"
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	GroupsClaim  string // claim with IdP group IDs, mapped to roles via app.idp_group_role_mappings
	// TrustEmail stores the email claim without email_verified. Only for IdPs that issue
	// nothing but addresses they control (a corporate directory that omits the claim).
	// Otherwise anyone could claim a colleague's address before their first sign-in.
	TrustEmail bool
	// RequiredACR, if set, is requested as acr_values and every ID token must carry exactly
	// this acr claim (e.g. the IdP's value for MFA); otherwise the sign-in fails ("claims").
	RequiredACR string
}

type Auth struct {
	cfg      Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	sessions *scs.SessionManager // user session, SameSite=Strict
	login    *scs.SessionManager // login transaction, SameSite=Lax (see NewSessions)
	st       *store.Store
}

const (
	keyUser     = "user_id"
	keyAuthTime = "auth_time" // last authentication at the IdP, for step-up (authz.v1.max_auth_age)
	keyState    = "oidc_state"
	keyNonce    = "oidc_nonce"
	keyVerifier = "oidc_verifier"
	keyReturn   = "return_to"
)

func New(ctx context.Context, cfg Config, sessions, login *scs.SessionManager, st *store.Store) (*Auth, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return &Auth{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		sessions: sessions,
		login:    login,
		st:       st,
	}, nil
}

// WithSession loads the user session and puts the signed-in user into the request
// context for authz. Only routes that need it use it: every loaded session is written
// back (idle timeout), which costs a database write per request.
func (a *Auth) WithSession(next http.Handler) http.Handler {
	return a.sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uid, ok := a.sessions.Get(r.Context(), keyUser).(int64); ok {
			// A session without auth_time (from before step-up existed) counts as too old.
			r = r.WithContext(authz.WithSignIn(r.Context(), uid, time.Unix(a.sessions.GetInt64(r.Context(), keyAuthTime), 0)))
			telemetry.SetUserID(r.Context(), uid)
		}
		next.ServeHTTP(w, r)
	}))
}

// LoginHandler starts the OIDC login (GET /auth/login). Optional query parameters:
// reauth=1 makes the IdP authenticate the user again even with an IdP session (step-up),
// return=<path> is where the user lands afterwards: a same-origin path, see safeReturn.
func (a *Auth) LoginHandler() http.Handler {
	return a.login.LoadAndSave(http.HandlerFunc(a.startLogin))
}

// CallbackHandler finishes it (GET /auth/callback) and starts the user session.
func (a *Auth) CallbackHandler() http.Handler {
	return a.sessions.LoadAndSave(a.login.LoadAndSave(http.HandlerFunc(a.finishLogin)))
}

// LogoutHandler ends the user session (POST /auth/logout).
func (a *Auth) LogoutHandler() http.Handler {
	return a.sessions.LoadAndSave(http.HandlerFunc(a.logout))
}

func (a *Auth) startLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	returnTo := "/"
	if q.Has("return") {
		if returnTo = q.Get("return"); !safeReturn(returnTo) {
			http.Error(w, "invalid return path", http.StatusBadRequest)
			return
		}
	}
	state, nonce, verifier := rand.Text(), rand.Text(), oauth2.GenerateVerifier()
	a.login.Put(ctx, keyState, state)
	a.login.Put(ctx, keyNonce, nonce)
	a.login.Put(ctx, keyVerifier, verifier)
	a.login.Put(ctx, keyReturn, returnTo)
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if a.cfg.RequiredACR != "" {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", a.cfg.RequiredACR))
	}
	if q.Get("reauth") == "1" {
		// Both, because IdPs differ in which one they honour. The session's auth time is the
		// ID token's auth_time: an IdP that ignores both but sends auth_time fails step-up
		// again. One that sends no auth_time is trusted to have re-authenticated.
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "0"), oauth2.SetAuthURLParam("prompt", "login"))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

// Same-origin paths only: "/" plus unreserved URL characters, the first not a slash.
// No "//host", "/\host", scheme, percent-encoding, whitespace or control characters,
// so no browser can read it as another origin (open redirect).
var returnPath = regexp.MustCompile(`^/([A-Za-z0-9._~?#=&-][A-Za-z0-9._~/?#=&-]*)?$`)

func safeReturn(p string) bool { return len(p) <= 200 && returnPath.MatchString(p) }

func (a *Auth) finishLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	state, nonce, verifier := a.login.GetString(ctx, keyState), a.login.GetString(ctx, keyNonce), a.login.GetString(ctx, keyVerifier)
	returnTo := a.login.GetString(ctx, keyReturn)
	// One attempt per login transaction, whatever the outcome.
	if err := a.login.Destroy(ctx); err != nil {
		a.fail(w, r, "login_transaction", err)
		return
	}
	if idpErr := q.Get("error"); idpErr != "" {
		a.fail(w, r, "idp_error", fmt.Errorf("idp returned %.100q", idpErr))
		return
	}
	if state == "" || q.Get("state") != state {
		a.fail(w, r, "state", nil)
		return
	}

	tok, err := a.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		a.fail(w, r, "code_exchange", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil || idt.Nonce != nonce {
		a.fail(w, r, "id_token", err)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		a.fail(w, r, "claims", err)
		return
	}
	if a.cfg.RequiredACR != "" && claims["acr"] != a.cfg.RequiredACR {
		a.fail(w, r, "claims", fmt.Errorf("acr %.100q, want %q", fmt.Sprint(claims["acr"]), a.cfg.RequiredACR))
		return
	}

	var uid int64
	err = a.st.AsLogin(ctx, func(q *db.Queries) (err error) {
		uid, err = q.UpsertLoginUser(ctx, db.UpsertLoginUserParams{
			Issuer: idt.Issuer, Subject: idt.Subject, Email: a.verifiedEmail(claims), DisplayName: str(claims["name"]),
		})
		if err != nil {
			return err
		}
		if err := q.SyncIdpRoles(ctx, db.SyncIdpRolesParams{UserID: uid, Issuer: idt.Issuer, GroupIds: strs(claims[a.cfg.GroupsClaim])}); err != nil {
			return err
		}
		return q.RecordAuthEvent(ctx, db.RecordAuthEventParams{
			Op: "LOGIN", UserID: &uid, Issuer: &idt.Issuer, Subject: &idt.Subject, ClientIp: clientIP(r),
		})
	})
	if err != nil {
		a.fail(w, r, syncFailure(err), err)
		return
	}

	// New session token on privilege change: prevents session fixation.
	if err := a.sessions.RenewToken(ctx); err != nil {
		a.fail(w, r, "session", err)
		return
	}
	a.sessions.Put(ctx, keyUser, uid)
	telemetry.SetUserID(ctx, uid)
	// Unix seconds: gob encodes an int64 session value without registration.
	a.sessions.Put(ctx, keyAuthTime, authTime(claims, time.Now()).Unix())
	// Checked at the start too; checked again so the redirect never depends on the store alone.
	if !safeReturn(returnTo) {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if uid, ok := a.sessions.Get(ctx, keyUser).(int64); ok {
		a.record(ctx, db.RecordAuthEventParams{Op: "LOGOUT", UserID: &uid, ClientIp: clientIP(r)})
	}
	if err := a.sessions.Destroy(ctx); err != nil {
		slog.ErrorContext(ctx, "logout failed", "err", err)
		http.Error(w, "sign-out failed, please try again", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// fail answers with a generic message and audits the failed step (a fixed code, see
// app.record_auth_event); the error text goes to the log only.
func (a *Auth) fail(w http.ResponseWriter, r *http.Request, step string, err error) {
	slog.WarnContext(r.Context(), "sign-in failed", "step", step, "err", err)
	a.record(r.Context(), db.RecordAuthEventParams{Op: "LOGIN_FAILED", Detail: &step, ClientIp: clientIP(r)})
	http.Error(w, "sign-in failed, please try again", http.StatusUnauthorized)
}

func (a *Auth) record(ctx context.Context, ev db.RecordAuthEventParams) {
	err := a.st.AsLogin(ctx, func(q *db.Queries) error { return q.RecordAuthEvent(ctx, ev) })
	if err != nil {
		slog.ErrorContext(ctx, "audit of auth event failed", "op", ev.Op, "err", err)
	}
}

// verifiedEmail is the email claim if the IdP vouches for it. Role management finds
// users by this address, so an unverified one could be a colleague's.
func (a *Auth) verifiedEmail(claims map[string]any) *string {
	if verified, _ := claims["email_verified"].(bool); verified || a.cfg.TrustEmail {
		return str(claims["email"])
	}
	return nil
}

// syncFailure is the audit code for a failed user sync at sign-in.
func syncFailure(err error) string {
	if errors.Is(err, store.ErrUserDisabled) {
		return "disabled"
	}
	return "user_sync"
}

// authTime is the ID token's auth_time (when the IdP last authenticated the user, which can
// be long before this sign-in with an IdP session), else now. Never later than now.
func authTime(claims map[string]any, now time.Time) time.Time {
	if s, ok := claims["auth_time"].(float64); ok {
		if t := time.Unix(int64(s), 0); t.Before(now) {
			return t
		}
	}
	return now
}

func clientIP(r *http.Request) *netip.Addr {
	ip, err := netip.ParseAddr(ratelimit.ClientIP(r))
	if err != nil {
		return nil
	}
	return &ip
}

func str(v any) *string {
	if s, ok := v.(string); ok && s != "" {
		return &s
	}
	return nil
}

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
