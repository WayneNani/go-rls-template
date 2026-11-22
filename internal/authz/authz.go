// Package authz enforces the privilege every RPC declares in the proto contract.
// A method without a declaration is denied. Row scope (which org) is enforced by
// Postgres RLS; this is the coarse gate in front of it.
package authz

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	authzv1 "example.com/starter/gen/authz/v1"
)

const (
	Public        = "public"        // no session; allowlisted in internal/api/contract_test.go
	Authenticated = "authenticated" // any signed-in user
)

// ReauthRequired is the message of the FailedPrecondition error a method with
// option (authz.v1.max_auth_age) returns when the sign-in is too old. The frontend
// recognises it (isReauthRequired in src/lib/api.ts) and offers a re-authentication.
const ReauthRequired = "recent sign-in required"

type signIn struct {
	userID int64
	at     time.Time // when the user last authenticated at the IdP; zero means unknown (too old)
}

type userKey struct{}

// WithSignIn puts the signed-in user and the time of their last IdP authentication
// into the context. internal/auth calls it for every request with a session.
func WithSignIn(ctx context.Context, userID int64, authTime time.Time) context.Context {
	return context.WithValue(ctx, userKey{}, signIn{userID, authTime})
}

// WithUser is WithSignIn with a sign-in that happened just now. Tests only (forbidigo):
// in a request it would pass every step-up check.
func WithUser(ctx context.Context, userID int64) context.Context {
	return WithSignIn(ctx, userID, time.Now())
}

func UserID(ctx context.Context) (int64, bool) {
	s, ok := ctx.Value(userKey{}).(signIn)
	return s.userID, ok
}

func authTime(ctx context.Context) time.Time {
	s, _ := ctx.Value(userKey{}).(signIn)
	return s.at
}

// Privilege returns what a method declares, or "" when it declares nothing.
func Privilege(md protoreflect.MethodDescriptor) string {
	p, _ := proto.GetExtension(md.Options(), authzv1.E_Privilege).(string)
	return p
}

// MaxAuthAge returns the step-up window a method declares, or 0 when it declares none.
func MaxAuthAge(md protoreflect.MethodDescriptor) time.Duration {
	s, _ := proto.GetExtension(md.Options(), authzv1.E_MaxAuthAge).(uint32)
	return time.Duration(s) * time.Second
}

// Checker reports whether the user holds the privilege in at least one org.
type Checker func(ctx context.Context, userID int64, privilege string) (bool, error)

type interceptor struct{ check Checker }

func NewInterceptor(check Checker) connect.Interceptor { return interceptor{check} }

func (i interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.authorize(ctx, req.Spec()); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (i interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := i.authorize(ctx, conn.Spec()); err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

func (i interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i interceptor) authorize(ctx context.Context, spec connect.Spec) error {
	md, ok := spec.Schema.(protoreflect.MethodDescriptor)
	if !ok {
		return denied()
	}
	priv := Privilege(md)
	switch priv {
	case "":
		return denied()
	case Public:
		return nil
	}
	uid, ok := UserID(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))
	}
	if priv != Authenticated {
		allowed, err := i.check(ctx, uid, priv)
		if err != nil {
			slog.ErrorContext(ctx, "authorization check failed", "procedure", spec.Procedure, "err", err)
			return connect.NewError(connect.CodeInternal, errors.New("internal error"))
		}
		if !allowed {
			return denied()
		}
	}
	// After the privilege, so a re-authentication is only offered to those who may act.
	if maxAge := MaxAuthAge(md); maxAge > 0 && time.Since(authTime(ctx)) > maxAge {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New(ReauthRequired))
	}
	return nil
}

func denied() error {
	return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
}
