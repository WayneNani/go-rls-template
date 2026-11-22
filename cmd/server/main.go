// Command server is the only place that wires HTTP routes (forbidigo).
// Every route is listed in routes(); changes here need security review (CODEOWNERS).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"example.com/starter/internal/api"
	"example.com/starter/internal/auth"
	"example.com/starter/internal/ratelimit"
	"example.com/starter/internal/store"
	"example.com/starter/internal/telemetry"
	"example.com/starter/internal/web"
)

func main() {
	slog.SetDefault(slog.New(telemetry.NewLogHandler(slog.NewJSONHandler(os.Stdout, nil))))
	if err := run(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Off by default: secure cookies and a verified TLS connection to the database.
	insecureDev := os.Getenv("INSECURE_DEV") == "true"
	if insecureDev {
		slog.Warn("INSECURE_DEV=true: plain-HTTP cookies and unencrypted database connections allowed; local development only")
	}

	// Before the store: its query tracer uses the provider set here.
	shutdownTracing, err := telemetry.Setup(ctx)
	if err != nil {
		return err
	}
	defer func() {
		// After the server has drained (deferred first, runs last): flush pending spans.
		flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(flush); err != nil {
			slog.Error("flushing traces failed", "err", err)
		}
	}()

	st, err := store.Open(ctx, mustEnv("DATABASE_URL"), !insecureDev)
	if err != nil {
		return err
	}
	defer st.Close()

	sessions, login := auth.NewSessions(st.SessionStore(), !insecureDev)

	a, err := auth.New(ctx, auth.Config{
		Issuer:       mustEnv("OIDC_ISSUER"),
		ClientID:     mustEnv("OIDC_CLIENT_ID"),
		ClientSecret: mustEnv("OIDC_CLIENT_SECRET"),
		RedirectURL:  mustEnv("OIDC_REDIRECT_URL"),
		GroupsClaim:  envOr("OIDC_GROUPS_CLAIM", "groups"),
		TrustEmail:   os.Getenv("OIDC_TRUST_EMAIL") == "true",
		RequiredACR:  os.Getenv("OIDC_REQUIRED_ACR"),
	}, sessions, login, st)
	if err != nil {
		return err
	}

	csrf := http.NewCrossOriginProtection()
	csrf.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.WarnContext(r.Context(), "cross-origin request denied", "method", r.Method, "path", r.URL.Path,
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"), "origin", r.Header.Get("Origin"))
		http.Error(w, "cross-origin request denied", http.StatusForbidden)
	}))

	// Telemetry outermost: every response, denied ones too, gets a request id and an access log line.
	handler := telemetry.Middleware(web.SecurityHeaders(csrf.Handler(routes(st, a))))

	srv := &http.Server{
		Addr:              envOr("LISTEN_ADDR", "127.0.0.1:8090"),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained // ListenAndServe returns at once; the deferred flush and Close wait for open requests
	return nil
}

func routes(st *store.Store, a *auth.Auth) http.Handler {
	// Per client IP. Many users can share one IP (office NAT), so these bound floods,
	// not single users: passwords live at the IdP, and every auth request is audited.
	var (
		apiLimit    = ratelimit.PerIP(20, 60)                        // 20/s, bursts of 60
		authLimit   = ratelimit.PerIP(1, 30)                         // 60/min, bursts of 30
		reportLimit = ratelimit.PerIP(rate.Every(2*time.Second), 20) // 30/min: every report is logged
	)
	// Rate limits run before the session is loaded, so a flood costs no database work.
	// Static files, the SPA and health checks never touch the session.
	mux := http.NewServeMux()
	mux.Handle("POST /api/", apiLimit.Wrap(a.WithSession(http.StripPrefix("/api", api.NewHandler(st)))))
	mux.Handle("GET /auth/login", authLimit.Wrap(a.LoginHandler()))
	mux.Handle("GET /auth/callback", authLimit.Wrap(a.CallbackHandler()))
	mux.Handle("POST /auth/logout", authLimit.Wrap(a.LogoutHandler()))
	mux.Handle("POST /csp-report", reportLimit.Wrap(http.HandlerFunc(web.CSPReport)))
	mux.Handle("GET /healthz", apiLimit.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := st.Ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})))
	mux.Handle("GET /", web.SPA())
	return mux
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing required environment variable", "key", key)
		os.Exit(1)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
