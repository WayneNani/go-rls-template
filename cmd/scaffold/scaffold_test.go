package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRejectsUnsafeInput(t *testing.T) {
	for _, tc := range []struct{ name, plural, fields, want string }{
		{"Invoice", "", "title:text", "snake_case"},
		{"invoice;drop", "", "title:text", "snake_case"},
		{"line2", "", "title:text", "snake_case"},
		{"select", "", "title:text", "reserved"},
		{"project", "", "title:text", "reserved"},
		{"invoice", "", "", "at least one"},
		{"invoice", "", "amount:int", "must be text"},
		{"invoice", "", "title:text title:int", "duplicate"},
		{"invoice", "", "title:text cost:money", "type one of"},
		{"invoice", "", "title:text org_id:int", "reserved"},
		{"invoice", "", "title:text from:text", "reserved"},
		{"invoice", "", `title:text x');drop:text`, "snake_case"},
		{"news", "news", "title:text", "differ"},
		{strings.Repeat("a", 31), "", "title:text", "30 characters"},
	} {
		_, err := parse(tc.name, tc.plural, tc.fields)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parse(%q, %q, %q) = %v, want an error with %q", tc.name, tc.plural, tc.fields, err, tc.want)
		}
	}
	e, err := parse("purchase_order", "", "reference:text, supplier_id:int due:date paid:bool")
	if err != nil {
		t.Fatal(err)
	}
	if e.Plural != "purchase_orders" || e.PluralPascal() != "PurchaseOrders" || e.Fields[1].SQLC() != "SupplierID" ||
		e.Fields[1].ProtoGo() != "SupplierId" || e.Fields[1].Camel() != "supplierId" || e.Kebab() != "purchase-orders" {
		t.Errorf("names: %+v", e)
	}
	for in, want := range map[string]string{"category": "categories", "day": "days", "box": "boxes", "batch": "batches"} {
		if got := pluralize(in); got != want {
			t.Errorf("pluralize(%q) = %q, want %q", in, got, want)
		}
	}
}

// Guard against template rot: scaffolds two entities into a copy of the repository and runs
// what `make check` runs there (generate, linters, the Go tests with the database). A template
// that stops matching the rules of this repo fails here, not in the next project that uses it.
func TestScaffoldedEntitiesPassTheChecks(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repo, "frontend/node_modules/.bin/protoc-gen-es")); err != nil {
		t.Fatal("frontend dependencies missing (make frontend-deps):", err)
	}
	dir := t.TempDir()
	ctx := context.Background()
	run := func(cwd string, cmd *exec.Cmd) string {
		t.Helper()
		cmd.Dir = cwd
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		return string(out)
	}

	// The working tree as git sees it (tracked and new files, no ignored ones), dependencies linked.
	src, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dst.Close() }()
	files := run(repo, exec.CommandContext(ctx, "git", "ls-files", "-co", "--exclude-standard"))
	for _, rel := range strings.Split(strings.TrimSpace(files), "\n") {
		b, err := src.ReadFile(rel)
		if os.IsNotExist(err) {
			continue // deleted in the working tree
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := dst.MkdirAll(filepath.Dir(rel), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := dst.WriteFile(rel, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(repo, "frontend/node_modules"), filepath.Join(dir, "frontend/node_modules")); err != nil {
		t.Fatal(err)
	}

	invoice, err := parse("invoice", "", "title:text amount:int due:date paid:bool note:text")
	if err != nil {
		t.Fatal(err)
	}
	order, err := parse("purchase_order", "", "reference:text supplier_id:int")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []entity{invoice, order} {
		if err := scaffold(dir, e); err != nil {
			t.Fatal(err)
		}
	}

	// A second run refuses and writes nothing.
	before, err := dst.ReadFile("internal/api/api.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := scaffold(dir, invoice); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Errorf("scaffolding invoice again: %v, want a refusal", err)
	}
	if after, _ := dst.ReadFile("internal/api/api.go"); !bytes.Equal(before, after) {
		t.Error("a refused scaffold changed internal/api/api.go")
	}

	// `make check` without actionlint (workflows are untouched) and without this package's own
	// tests (they would recurse).
	web := filepath.Join(dir, "frontend")
	run(dir, exec.CommandContext(ctx, "make", "generate", "lint-rules", "lint-migrations"))
	run(dir, exec.CommandContext(ctx, "go", "tool", "-modfile=tools/go.mod", "buf", "lint"))
	run(dir, exec.CommandContext(ctx, "go", "tool", "-modfile=tools/go.mod", "golangci-lint", "run", "./..."))
	run(web, exec.CommandContext(ctx, "node_modules/.bin/tsc"))
	run(web, exec.CommandContext(ctx, "node_modules/.bin/eslint", "."))
	run(dir, exec.CommandContext(ctx, "go", "test", "-count=1", "./internal/..."))
}
