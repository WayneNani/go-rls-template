package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"example.com/starter/internal/store/db"
)

// Database spans carry the SQL text but never an argument: not as an attribute, not in
// an error message that echoes the value (Postgres does for invalid input), not in a
// client-side encode error.
func TestSpansNeverContainQueryArguments(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_ADMIN_URL")
	if url == "" {
		t.Fatal("TEST_DATABASE_ADMIN_URL is not set (run tests through `make test`)")
	}
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otel.SetTracerProvider(tp) // the only test in this package that sets it

	ctx := context.Background()
	st, err := Open(ctx, url, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	const secret = "s3cret-argument-value"
	ctx, parent := tp.Tracer("test").Start(ctx, "test") // otelpgx records only under a recording span
	if _, err := st.pool.Exec(ctx, "select $1::text", secret); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, "select $1::text::int", secret); err == nil || !strings.Contains(err.Error(), secret) {
		t.Fatalf("want a Postgres error that echoes the argument (so the test means something), got %v", err)
	}
	_, _ = st.pool.Exec(ctx, "select $1::int", secret) // client-side encode error
	if err := st.WithUser(ctx, 987654321, func(*db.Queries) error { return nil }); err != nil {
		t.Fatal(err)
	}
	parent.End()

	var sawSQL, sawError bool
	for _, s := range exp.GetSpans() {
		dump := fmt.Sprintf("%s %v %v %v %v", s.Name, s.Attributes, s.Events, s.Status, s.Links)
		for _, arg := range []string{secret, "987654321"} {
			if strings.Contains(dump, arg) {
				t.Errorf("span %q contains query argument %q: %s", s.Name, arg, dump)
			}
		}
		sawSQL = sawSQL || strings.Contains(dump, "select $1::text::int")
		sawError = sawError || s.Status.Code == codes.Error
	}
	if !sawSQL || !sawError {
		t.Fatalf("want spans with SQL text and a failed statement, got sql=%v error=%v", sawSQL, sawError)
	}
}
