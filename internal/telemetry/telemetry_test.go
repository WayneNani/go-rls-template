package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/protobuf/types/known/emptypb"
)

const incomingTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"

// One request through the middleware and a Connect handler: logs carry request id, trace id
// and user id, the access log has the route pattern and the Connect code, rejections log at
// info, and neither logs nor spans contain emails, cookies, tokens or the query string.
func TestRequestLogsAndSpans(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
	otel.SetTextMapPropagator(propagation.TraceContext{})
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(NewLogHandler(slog.NewJSONHandler(&logs, nil))))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rpc := connect.NewUnaryHandler("/test.v1.Svc/Do",
		func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
		}, connect.WithInterceptors(Interceptors()...))
	// Stands in for the ServeMux of cmd/server (forbidigo), which sets the pattern the same way.
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test.v1.Svc/Do" {
			r.Pattern = "POST /test.v1.Svc/Do"
			rpc.ServeHTTP(w, r)
			return
		}
		r.Pattern = "GET /items/{id}"
		SetUserID(r.Context(), 42)
		slog.InfoContext(r.Context(), "inside", "email", "a@b.example", "note", "contact alice@example.com",
			"err", errors.New("lookup of bob@example.org failed"), slog.Group("g", "to", "carol@example.net"))
	})
	srv := httptest.NewServer(Middleware(mux))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/items/123?code=SECRET-CODE", nil)
	req.Header.Set("Cookie", "session=SECRET-COOKIE")
	req.Header.Set("Authorization", "Bearer SECRET-TOKEN")
	req.Header.Set("traceparent", "00-"+incomingTraceID+"-00f067aa0ba902b7-01")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	requestID := res.Header.Get(RequestIDHeader)
	if requestID == "" {
		t.Fatal("no request id header")
	}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/test.v1.Svc/Do", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	lines := map[string][]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		lines[m["msg"].(string)] = append(lines[m["msg"].(string)], m)
	}
	inside, access := lines["inside"][0], lines["request"][0]
	for _, m := range []map[string]any{inside, access} {
		if m["request_id"] != requestID || m["trace_id"] != incomingTraceID || m["user_id"] != float64(42) {
			t.Errorf("want request_id %s, trace_id %s, user_id 42: %v", requestID, incomingTraceID, m)
		}
	}
	if access["route"] != "GET /items/{id}" || access["status"] != float64(200) || access["method"] != "GET" {
		t.Errorf("access log: %v", access)
	}
	rejected, rpcLog := lines["rpc rejected"], lines["request"][1]
	if len(rejected) != 1 || rejected[0]["level"] != "INFO" || rejected[0]["procedure"] != "/test.v1.Svc/Do" {
		t.Errorf("want one info line for the denial: %v", rejected)
	}
	if rpcLog["procedure"] != "/test.v1.Svc/Do" || rpcLog["code"] != "permission_denied" {
		t.Errorf("access log of the RPC: %v", rpcLog)
	}

	var spans strings.Builder
	for _, s := range exp.GetSpans() {
		fmt.Fprintf(&spans, "%s %v %v %v\n", s.Name, s.Attributes, s.Events, s.Status)
		if s.Name == "GET /items/{id}" && s.SpanContext.TraceID().String() != incomingTraceID {
			t.Errorf("server span not parented on the incoming traceparent: %s", s.SpanContext.TraceID())
		}
	}
	if !strings.Contains(spans.String(), "GET /items/{id}") || !strings.Contains(spans.String(), "test.v1.Svc/Do") {
		t.Errorf("want HTTP and RPC spans, got:\n%s", spans.String())
	}
	for _, leak := range []string{"SECRET", "@example", "@b.example", "/items/123"} {
		if strings.Contains(logs.String(), leak) {
			t.Errorf("log contains %q:\n%s", leak, logs.String())
		}
		if strings.Contains(spans.String(), leak) {
			t.Errorf("span contains %q:\n%s", leak, spans.String())
		}
	}
}
