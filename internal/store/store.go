// Package store is the only way to the database (enforced by depguard).
// Every query runs in a transaction whose RLS identity is set first.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for goose
	"github.com/pressly/goose/v3"

	"example.com/starter/internal/store/db"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	ErrForbidden    = errors.New("forbidden by row-level security")
	ErrInvalid      = errors.New("invalid input")
	ErrNotFound     = errors.New("no row (missing or hidden by row-level security)")
	ErrUserDisabled = errors.New("user is disabled") // sign-in refused, see app.upsert_login_user
)

type Store struct{ pool *pgxpool.Pool }

// Open connects as the runtime role (app_rw). With requireTLS, a URL that does not
// verify the server certificate and host name (sslmode=verify-full) is refused.
func Open(ctx context.Context, url string, requireTLS bool) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if requireTLS {
		if err := checkTLS(cfg.ConnConfig.Config); err != nil {
			return nil, err
		}
	}
	// Set pool_max_conns in the URL; pgx's own default grows with the CPU count, which can
	// exhaust max_connections when several instances run on large machines.
	if !strings.Contains(url, "pool_max_conns") {
		cfg.MaxConns = 10
	}
	cfg.ConnConfig.Tracer = queryTracer() // SQL text only, never arguments (trace.go)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Ping reports whether the database answers (health check).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

var errInsecureDB = errors.New("database connection must use sslmode=verify-full")

// checkTLS accepts only connections that encrypt and verify certificate and host name,
// including every fallback (sslmode=prefer would silently fall back to plain text).
func checkTLS(c pgconn.Config) error {
	if c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify {
		return errInsecureDB
	}
	for _, fb := range c.Fallbacks {
		if fb.TLSConfig == nil || fb.TLSConfig.InsecureSkipVerify {
			return errInsecureDB
		}
	}
	return nil
}

// SessionStore keeps HTTP sessions in app.sessions.
func (s *Store) SessionStore() *pgxstore.PostgresStore {
	return pgxstore.NewWithConfig(s.pool, pgxstore.Config{TableName: "app.sessions", CleanUpInterval: 5 * time.Minute})
}

// WithUser runs fn in one transaction whose RLS identity is userID.
func (s *Store) WithUser(ctx context.Context, userID int64, fn func(*db.Queries) error) error {
	return s.tx(ctx, strconv.FormatInt(userID, 10), fn)
}

// AsLogin runs fn without a user identity. Only the login flow uses it
// (upsert the user, sync IdP roles), through SECURITY DEFINER functions.
func (s *Store) AsLogin(ctx context.Context, fn func(*db.Queries) error) error {
	return s.tx(ctx, "", fn)
}

// HasPrivilege reports whether the user holds the privilege in any org.
func (s *Store) HasPrivilege(ctx context.Context, userID int64, privilege string) (allowed bool, err error) {
	err = s.WithUser(ctx, userID, func(q *db.Queries) error {
		allowed, err = q.HasPrivilegeAnywhere(ctx, privilege)
		return err
	})
	return allowed, err
}

func (s *Store) tx(ctx context.Context, userID string, fn func(*db.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// true = transaction-local, so a pooled connection never carries the identity on.
	if _, err := tx.Exec(ctx, "select set_config('app.user_id', $1, true)", userID); err != nil {
		return err
	}
	if err := fn(db.New(tx)); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit(ctx))
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "42501": // insufficient_privilege, incl. RLS WITH CHECK violations
			return fmt.Errorf("%w: %s", ErrForbidden, pgErr.Message)
		case "23502", "23503", "23505", "23514", "23P01", "22001", "P0003": // not null, foreign key, unique, check, exclusion, too long, ambiguous
			return fmt.Errorf("%w: %w", ErrInvalid, pgErr) // keeps the constraint name for ConstraintName
		case "P0004":
			return ErrUserDisabled
		}
	}
	return err
}

// ConstraintName is the named constraint an ErrInvalid violated, or "". The api package maps
// it to a request field (constraintFields); the name itself never reaches a client.
func ConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

// Migrate applies the embedded migrations as the owner role (app_owner).
// The server never gets these credentials; cmd/migrate runs before a deploy.
// With requireTLS the same sslmode=verify-full rule applies as for the server.
func Migrate(ctx context.Context, ownerURL string, requireTLS bool) error {
	if requireTLS {
		cfg, err := pgconn.ParseConfig(ownerURL)
		if err != nil {
			return err
		}
		if err := checkTLS(*cfg); err != nil {
			return err
		}
	}
	sqlDB, err := sql.Open("pgx", ownerURL)
	if err != nil {
		return err
	}
	defer func() { _ = sqlDB.Close() }()
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys)
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}
