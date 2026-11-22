package api_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	validatepb "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	appv1 "example.com/starter/gen/app/v1"
	"example.com/starter/gen/app/v1/appv1connect"
	"example.com/starter/internal/api" // registers every served service
	"example.com/starter/internal/authz"
	"example.com/starter/internal/store"
	"example.com/starter/internal/testdb"
)

// Methods reachable without a session. Adding one here needs security review (CODEOWNERS).
var publicAllowlist = map[protoreflect.FullName]bool{}

// Step-up: every method that needs one of these privileges must declare
// option (authz.v1.max_auth_age) of at most maxStepUpAge, so an access change always
// needs a recent sign-in. A new method under such a privilege fails until it declares it
// or, if it only reads, is added to stepUpExempt (security review, CODEOWNERS). Removing
// the option from a method, or raising it to hours, fails the same way.
var (
	stepUpPrivileges = map[string]bool{"access.manage": true}
	stepUpExempt     = map[protoreflect.FullName]bool{
		"access.v1.AccessService.ListMembers":       true, // read only
		"access.v1.AccessService.ListGroupMappings": true, // read only
	}
)

const maxStepUpAge = 15 * time.Minute

// List RPCs that return everything at once. Each needs a reason (security review, CODEOWNERS);
// every other List* takes page_size (with an upper bound) and page_token and returns
// next_page_token.
var unpagedLists = map[protoreflect.FullName]string{
	"access.v1.AccessService.ListRoles": "the role catalog: a few rows, maintained in migrations only",
}

func appMethods(t *testing.T) []protoreflect.MethodDescriptor {
	t.Helper()
	var out []protoreflect.MethodDescriptor
	// Every service in our proto/ tree, not everything registered: dependencies link in
	// services we never serve (the OTLP exporter brings OTLP and grpc.health). A file of
	// ours that is not linked into the server fails, so none can slip past these tests.
	err := filepath.WalkDir("../../proto", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".proto" {
			return err
		}
		rel, err := filepath.Rel("../../proto", path)
		if err != nil {
			return err
		}
		fd, err := protoregistry.GlobalFiles.FindFileByPath(filepath.ToSlash(rel))
		if err != nil {
			return fmt.Errorf("%s is not linked into the server: %w", path, err)
		}
		for i := range fd.Services().Len() {
			ms := fd.Services().Get(i).Methods()
			for j := range ms.Len() {
				out = append(out, ms.Get(j))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no services found under proto/")
	}
	return out
}

func TestEveryMethodDeclaresPrivilege(t *testing.T) {
	for _, md := range appMethods(t) {
		switch p := authz.Privilege(md); {
		case p == "":
			t.Errorf("%s: missing option (authz.v1.privilege)", md.FullName())
		case p == authz.Public && !publicAllowlist[md.FullName()]:
			t.Errorf("%s: public but not on the allowlist", md.FullName())
		}
	}
}

func TestDeclaredPrivilegesExistInCatalog(t *testing.T) {
	db := testdb.New(t)
	for _, md := range appMethods(t) {
		p := authz.Privilege(md)
		if p == "" || p == authz.Public || p == authz.Authenticated {
			continue
		}
		var exists bool
		err := db.Admin.QueryRow(context.Background(),
			"select exists (select 1 from app.privileges where code = $1)", p).Scan(&exists)
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("%s: privilege %q is not in app.privileges", md.FullName(), p)
		}
	}
}

func TestAccessChangesNeedRecentSignIn(t *testing.T) {
	for _, md := range appMethods(t) {
		p, age := authz.Privilege(md), authz.MaxAuthAge(md)
		switch {
		case age > 0 && p == authz.Public:
			t.Errorf("%s: max_auth_age on a public method is never checked", md.FullName())
		case !stepUpPrivileges[p] || stepUpExempt[md.FullName()]:
		case age == 0:
			t.Errorf("%s: needs %q but declares no option (authz.v1.max_auth_age)", md.FullName(), p)
		case age > maxStepUpAge:
			t.Errorf("%s: max_auth_age %v is longer than %v", md.FullName(), age, maxStepUpAge)
		}
	}
}

func fieldRules(fd protoreflect.FieldDescriptor) *validatepb.FieldRules {
	r, _ := proto.GetExtension(fd.Options(), validatepb.E_Field).(*validatepb.FieldRules)
	return r
}

// requestFields calls fn for every field of every request message, nested messages included.
func requestFields(t *testing.T, fn func(protoreflect.FieldDescriptor)) {
	seen := map[protoreflect.FullName]bool{}
	var walk func(protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] || strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
			return
		}
		seen[md.FullName()] = true
		for i := range md.Fields().Len() {
			fd := md.Fields().Get(i)
			fn(fd)
			if fd.Message() != nil && !fd.IsMap() {
				walk(fd.Message())
			}
		}
	}
	for _, md := range appMethods(t) {
		walk(md.Input())
	}
}

// Input rules live in proto (protovalidate) and the server enforces them for every RPC
// (NewHandler). A field without a rule fails here; one that needs none says so with
// (buf.validate.field).ignore = IGNORE_ALWAYS.
func TestEveryRequestFieldHasRules(t *testing.T) {
	requestFields(t, func(fd protoreflect.FieldDescriptor) {
		if proto.Size(fieldRules(fd)) == 0 {
			t.Errorf("%s: no (buf.validate.field) rule; add one, or ignore: IGNORE_ALWAYS if it truly needs none", fd.FullName())
		}
	})
	// A rule that does not fit its field (int32 rules on a string, a CEL typo) fails at
	// compile time: here, not at the first request.
	v, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, md := range appMethods(t) {
		err := v.Validate(dynamicpb.NewMessage(md.Input()))
		if ce, re := new(protovalidate.CompilationError), new(protovalidate.RuntimeError); errors.As(err, &ce) || errors.As(err, &re) {
			t.Errorf("%s: %v", md.Input().FullName(), err)
		}
	}
}

func TestListsArePaginated(t *testing.T) {
	for _, md := range appMethods(t) {
		if !strings.HasPrefix(string(md.Name()), "List") || unpagedLists[md.FullName()] != "" {
			continue
		}
		in, out := md.Input().Fields(), md.Output().Fields()
		switch size := in.ByName("page_size"); {
		case size == nil || size.Kind() != protoreflect.Int32Kind:
			t.Errorf("%s: request needs int32 page_size", md.FullName())
		case fieldRules(size).GetInt32().GetLessThan() == nil:
			t.Errorf("%s: page_size needs an upper bound, (buf.validate.field).int32.lte", md.FullName())
		}
		if f := in.ByName("page_token"); f == nil || f.Kind() != protoreflect.StringKind {
			t.Errorf("%s: request needs string page_token", md.FullName())
		}
		if f := out.ByName("next_page_token"); f == nil || f.Kind() != protoreflect.StringKind {
			t.Errorf("%s: response needs string next_page_token", md.FullName())
		}
	}
}

// Authorization runs before validation: a caller who may not call a method learns nothing
// about its rules, and a caller who may gets the violations to show at the field.
func TestValidationAfterAuthorization(t *testing.T) {
	ctx := context.Background()
	db := testdb.New(t)
	_, err := db.Admin.Exec(ctx, `
		insert into app.orgs (name) values ('Acme');
		insert into app.users (issuer, subject) values ('test', 'viewer'), ('test', 'editor');
		insert into app.role_assignments (user_id, role_code, org_id)
		select u.id, u.subject, o.id from app.users u, app.orgs o;`)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, u := range []string{"viewer", "editor"} {
		var id int64
		if err := db.Admin.QueryRow(ctx, "select id from app.users where subject = $1", u).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[u] = id
	}
	st, err := store.Open(ctx, db.AppURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	srv := httptest.NewServer(testIdentity(api.NewHandler(st)))
	t.Cleanup(srv.Close)
	client := appv1connect.NewAppServiceClient(srv.Client(), srv.URL)

	invalid := &appv1.CreateProjectRequest{Name: strings.Repeat("x", 101)} // and org_id 0
	for _, tc := range []struct {
		user string
		want connect.Code
	}{
		{"", connect.CodeUnauthenticated},
		{"viewer", connect.CodePermissionDenied},
		{"editor", connect.CodeInvalidArgument},
	} {
		_, err := client.CreateProject(ctx, as(tc.user, ids, invalid))
		var fields []string
		if ce := new(connect.Error); errors.As(err, &ce) {
			for _, d := range ce.Details() {
				if v, err := d.Value(); err == nil {
					if vs, ok := v.(*validatepb.Violations); ok {
						for _, x := range vs.GetViolations() {
							fields = append(fields, protovalidate.FieldPathString(x.GetField()))
						}
					}
				}
			}
		}
		if got := connect.CodeOf(err); got != tc.want {
			t.Errorf("%q: got %v, want %v (%v)", tc.user, got, tc.want, err)
		}
		wantFields := []string(nil)
		if tc.want == connect.CodeInvalidArgument {
			wantFields = []string{"org_id", "name"}
		}
		if slices.Sort(fields); !slices.Equal(fields, slices.Sorted(slices.Values(wantFields))) {
			t.Errorf("%q: violations on %v, want %v", tc.user, fields, wantFields)
		}
	}
}
