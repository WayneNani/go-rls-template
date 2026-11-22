// Package telemetry is the only place that sets up tracing (depguard): request ids, the
// access log, the request context and redaction of every log line, and the OpenTelemetry
// SDK with its OTLP exporter. Export is off unless OTEL_EXPORTER_OTLP_ENDPOINT (or
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) is set.
package telemetry

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// RequestIDHeader carries the server-generated request id in every response. Support
// matches it to the log; the frontend shows it in its generic error message.
const RequestIDHeader = "X-Request-Id"

// Setup installs the tracer provider and the W3C trace context propagator (no baggage:
// client-controlled data would travel on). Without an OTLP endpoint nothing is recorded or
// exported, but every request still gets a trace id for its logs. The returned function
// flushes the exporter; call it on shutdown.
func Setup(ctx context.Context) (shutdown func(context.Context) error, err error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		// NeverSample, not parent-based: a client's sampled flag cannot switch recording on.
		otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample())))
		return func(context.Context) error { return nil }, nil
	}
	// The exporter and the SDK read the other OTEL_* variables (headers, service name, sampler).
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
	otel.SetTracerProvider(tp)
	slog.InfoContext(ctx, "exporting traces via OTLP")
	return tp.Shutdown, nil
}

type requestInfo struct {
	id        string
	userID    int64  // internal id; 0 until the session is known
	procedure string // Connect procedure, set by the interceptor
	code      string // Connect code of the procedure's result
}

type infoKey struct{}

var tracer = otel.Tracer("example.com/starter/internal/telemetry")

// Middleware gives every request a request id (X-Request-Id), a server span (parented on
// an incoming traceparent, which is used for correlation only) and one access log line.
// It wraps the whole handler, so the ServeMux sets the route pattern on its request.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.Start(ctx, r.Method, trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()

		info := &requestInfo{id: rand.Text()}
		w.Header().Set(RequestIDHeader, info.id)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r = r.WithContext(context.WithValue(ctx, infoKey{}, info))
		next.ServeHTTP(rec, r)

		// Pattern, never the raw path or query (ids, OAuth code and state).
		route := r.Pattern
		if route != "" {
			span.SetName(route)
		}
		// Deliberately few attributes: no URL, query, headers, cookies or client address.
		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", rec.status),
			attribute.String("app.request_id", info.id),
		)
		if rec.status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(rec.status))
		}
		args := []any{"method", r.Method, "route", route, "status", rec.status,
			"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
		if info.procedure != "" {
			args = append(args, "procedure", info.procedure, "code", info.code)
		}
		slog.InfoContext(r.Context(), "request", args...)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// SetUserID records the signed-in user's internal id for the request's logs and span.
// Never pass email, subject or anything from the IdP.
func SetUserID(ctx context.Context, userID int64) {
	if info, ok := ctx.Value(infoKey{}).(*requestInfo); ok {
		info.userID = userID
	}
	trace.SpanFromContext(ctx).SetAttributes(attribute.Int64("app.user_id", userID))
}

// Interceptors trace each RPC (a child span of the HTTP span; no payloads, no headers) and
// log rejections. They go outermost in api.NewHandler, so they see authz and validation.
func Interceptors() []connect.Interceptor {
	otelI, err := otelconnect.NewInterceptor(otelconnect.WithoutMetrics())
	if err != nil {
		panic(err) // only metric setup can fail, and metrics are off
	}
	return []connect.Interceptor{otelI, logInterceptor{}}
}

type logInterceptor struct{}

func (logInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		recordRPC(ctx, req.Spec().Procedure, err)
		return res, err
	}
}

func (logInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		err := next(ctx, conn)
		recordRPC(ctx, conn.Spec().Procedure, err)
		return err
	}
}

func (logInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// recordRPC notes procedure and code for the access log and logs authz denials, step-up
// failures and validation failures at info: expected outcomes, but what support asks about.
func recordRPC(ctx context.Context, procedure string, err error) {
	code := "ok"
	if err != nil {
		code = connect.CodeOf(err).String()
	}
	if info, ok := ctx.Value(infoKey{}).(*requestInfo); ok {
		info.procedure, info.code = procedure, code
	}
	var ce *connect.Error
	if errors.As(err, &ce) {
		switch ce.Code() {
		case connect.CodeUnauthenticated, connect.CodePermissionDenied, connect.CodeFailedPrecondition, connect.CodeInvalidArgument:
			slog.InfoContext(ctx, "rpc rejected", "procedure", procedure, "code", code, "reason", ce.Message())
		}
	}
}

// NewLogHandler adds request id, trace id and user id to every record logged with a request
// context and redacts sensitive values: attributes whose key names a secret or personal
// datum, and anything that looks like an email address.
func NewLogHandler(h slog.Handler) slog.Handler { return logHandler{h} }

type logHandler struct{ slog.Handler }

func (h logHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, redactString(r.Message), r.PC)
	if info, ok := ctx.Value(infoKey{}).(*requestInfo); ok {
		out.AddAttrs(slog.String("request_id", info.id))
		if info.userID != 0 {
			out.AddAttrs(slog.Int64("user_id", info.userID))
		}
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		out.AddAttrs(slog.String("trace_id", sc.TraceID().String()))
	}
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redact(a))
		return true
	})
	return h.Handler.Handle(ctx, out)
}

func (h logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = redact(a)
	}
	return logHandler{h.Handler.WithAttrs(red)}
}

func (h logHandler) WithGroup(name string) slog.Handler { return logHandler{h.Handler.WithGroup(name)} }

var (
	sensitiveKey = regexp.MustCompile(`(?i)email|token|cookie|authorization|password|secret|body`)
	emailLike    = regexp.MustCompile(`[^\s@"'<>(),;:]+@[^\s@"'<>(),;:]+\.[A-Za-z]{2,}`)
)

func redact(a slog.Attr) slog.Attr {
	if sensitiveKey.MatchString(a.Key) {
		return slog.String(a.Key, "[redacted]")
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, redactString(v.String()))
	case slog.KindAny: // errors, structs, maps: their text may hold anything
		if v.Any() != nil {
			return slog.String(a.Key, redactString(fmt.Sprint(v.Any())))
		}
	case slog.KindGroup:
		g := v.Group()
		red := make([]any, len(g))
		for i, ga := range g {
			red[i] = redact(ga)
		}
		return slog.Group(a.Key, red...)
	}
	return slog.Attr{Key: a.Key, Value: v}
}

func redactString(s string) string { return emailLike.ReplaceAllString(s, "[email]") }
