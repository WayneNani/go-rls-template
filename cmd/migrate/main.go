// Command migrate applies the database migrations as the owner role.
// It runs as a separate deploy step; the server never holds owner credentials.
package main

import (
	"context"
	"log/slog"
	"os"

	"example.com/starter/internal/store"
)

func main() {
	url := os.Getenv("MIGRATE_DATABASE_URL")
	if url == "" {
		slog.Error("MIGRATE_DATABASE_URL is required")
		os.Exit(1)
	}
	// INSECURE_DEV=true (local development only) allows an unencrypted connection.
	if err := store.Migrate(context.Background(), url, os.Getenv("INSECURE_DEV") != "true"); err != nil {
		slog.Error("migration failed", "err", err)
		os.Exit(1)
	}
	slog.Info("migrations applied")
}
