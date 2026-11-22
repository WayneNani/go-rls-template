// Package testdb gives each test a fresh, migrated database. It fails (never skips)
// when Postgres is unreachable, so CI cannot pass by silently dropping the DB tests.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"example.com/starter/internal/store"
)

type DB struct {
	AppURL string        // runtime role app_rw
	Admin  *pgxpool.Pool // superuser, bypasses RLS: seeding and inspection only
}

func New(t *testing.T) DB {
	t.Helper()
	ctx := context.Background()
	adminURL := os.Getenv("TEST_DATABASE_ADMIN_URL")
	if adminURL == "" {
		t.Fatal("TEST_DATABASE_ADMIN_URL is not set (run tests through `make test`)")
	}

	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("test database unreachable (run `make up`): %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	_, file, _, _ := runtime.Caller(0)
	roles, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "dev", "roles.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// Test packages run in parallel; serialize the cluster-wide role setup.
	mustExec(t, conn, "select pg_advisory_lock(4711)")
	mustExec(t, conn, string(roles))
	mustExec(t, conn, "select pg_advisory_unlock(4711)")

	name := fmt.Sprintf("test_%d", time.Now().UnixNano())
	mustExec(t, conn, "create database "+name+" owner app_owner")
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), adminURL)
		if err == nil {
			_, _ = c.Exec(context.Background(), "drop database "+name+" with (force)")
			_ = c.Close(context.Background())
		}
	})

	if err := store.Migrate(ctx, withDB(adminURL, name, "app_owner", "app_owner"), false); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin, err := pgxpool.New(ctx, withDB(adminURL, name, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	return DB{AppURL: withDB(adminURL, name, "app_rw", "app_rw"), Admin: admin}
}

func mustExec(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// withDB swaps database name and, when user is set, the credentials.
func withDB(raw, db, user, password string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.Path = "/" + db
	if user != "" {
		u.User = url.UserPassword(user, password)
	}
	return u.String()
}
