package store

import (
	"context"
	"errors"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// queryTracer records a span per statement with the SQL text, never the arguments
// (otelpgx leaves them out unless WithIncludeQueryParameters) and never the result.
// Error messages can echo an argument ('invalid input syntax for type integer: "..."'),
// so a failed statement's span gets the SQLSTATE and constraint only (trace_test.go).
func queryTracer() pgx.QueryTracer {
	return redactingTracer{otelpgx.NewTracer()}
}

type redactingTracer struct{ *otelpgx.Tracer }

func (t redactingTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	data.Err = redactErr(data.Err)
	t.Tracer.TraceQueryEnd(ctx, conn, data)
}

func (t redactingTracer) TracePrepareEnd(ctx context.Context, conn *pgx.Conn, data pgx.TracePrepareEndData) {
	data.Err = redactErr(data.Err)
	t.Tracer.TracePrepareEnd(ctx, conn, data)
}

func redactErr(err error) error {
	var pgErr *pgconn.PgError
	switch {
	case err == nil, errors.Is(err, pgx.ErrNoRows), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.As(err, &pgErr):
		msg := "message redacted"
		if pgErr.ConstraintName != "" {
			msg += ", constraint " + pgErr.ConstraintName
		}
		return &pgconn.PgError{Severity: pgErr.Severity, Code: pgErr.Code, Message: msg, ConstraintName: pgErr.ConstraintName}
	default: // e.g. a client-side encode error quoting the value
		return errors.New("statement failed (details in the application log)")
	}
}
