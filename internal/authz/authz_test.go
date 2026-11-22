package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"

	accessv1 "example.com/starter/gen/access/v1"
)

func TestStepUp(t *testing.T) {
	methods := accessv1.File_access_v1_access_proto.Services().ByName("AccessService").Methods()
	grant, list := methods.ByName("GrantRole"), methods.ByName("ListMembers") // with and without max_auth_age
	if MaxAuthAge(grant) == 0 {
		t.Fatal("GrantRole declares no max_auth_age")
	}
	allow := NewInterceptor(func(context.Context, int64, string) (bool, error) { return true, nil }).(interceptor)
	deny := NewInterceptor(func(context.Context, int64, string) (bool, error) { return false, nil }).(interceptor)
	old := time.Now().Add(-MaxAuthAge(grant) - time.Minute)

	for _, tc := range []struct {
		name string
		i    interceptor
		ctx  context.Context
		md   protoreflect.MethodDescriptor
		want connect.Code // 0: allowed
	}{
		{"recent sign-in", allow, WithSignIn(t.Context(), 1, time.Now().Add(-time.Minute)), grant, 0},
		{"old sign-in", allow, WithSignIn(t.Context(), 1, old), grant, connect.CodeFailedPrecondition},
		{"unknown sign-in time (old session)", allow, WithSignIn(t.Context(), 1, time.Time{}), grant, connect.CodeFailedPrecondition},
		{"privilege before step-up", deny, WithSignIn(t.Context(), 1, old), grant, connect.CodePermissionDenied},
		{"no session", allow, t.Context(), grant, connect.CodeUnauthenticated},
		{"method without step-up", allow, WithSignIn(t.Context(), 1, old), list, 0},
	} {
		err := tc.i.authorize(tc.ctx, connect.Spec{Schema: tc.md})
		got := connect.Code(0)
		if err != nil {
			got = connect.CodeOf(err)
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v (%v)", tc.name, got, tc.want, err)
		}
		if ce := new(connect.Error); got == connect.CodeFailedPrecondition && errors.As(err, &ce) && ce.Message() != ReauthRequired {
			t.Errorf("%s: message %q, the frontend looks for %q", tc.name, ce.Message(), ReauthRequired)
		}
	}
}
