package api_test

import (
	"bufio"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	validatepb "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"connectrpc.com/connect"

	accessv1 "example.com/starter/gen/access/v1"
	"example.com/starter/gen/access/v1/accessv1connect"
	appv1 "example.com/starter/gen/app/v1"
	"example.com/starter/gen/app/v1/appv1connect"
	"example.com/starter/internal/api"
	"example.com/starter/internal/authz"
	"example.com/starter/internal/store"
	"example.com/starter/internal/testdb"
)

const (
	ok     connect.Code = 0
	unauth              = connect.CodeUnauthenticated
	denied              = connect.CodePermissionDenied
)

const matrixFile = "../../docs/access-matrix.md"

// Personas of docs/access-matrix.md, plus "target" (an email-addressable user without roles).
const seed = `
insert into app.orgs (name) values ('Acme'), ('Globex');
insert into app.users (issuer, subject, email) values
  ('test', 'nobody', null), ('test', 'viewerAcme', null), ('test', 'editorAcme', null),
  ('test', 'adminAcme', null), ('test', 'editorGlobex', null), ('test', 'target', 'target@example.test');
insert into app.role_assignments (user_id, role_code, org_id)
select u.id, v.role, o.id
  from (values ('viewerAcme', 'viewer', 'Acme'), ('editorAcme', 'editor', 'Acme'), ('adminAcme', 'admin', 'Acme'),
               ('editorGlobex', 'editor', 'Globex')) v (subject, role, org)
  join app.users u on u.subject = v.subject
  join app.orgs o on o.name = v.org;
insert into app.projects (org_id, name)
select id, name || ' roadmap' from app.orgs;
-- scaffold: seed rows above this line
`

// A call is one row of the matrix. method names the RPC it exercises; every RPC needs a row.
type call struct {
	method string
	do     func(ctx context.Context, user string) error
}

// TestRoleMatrix runs docs/access-matrix.md against the real stack.
func TestRoleMatrix(t *testing.T) {
	ctx := context.Background()
	db := testdb.New(t)
	if _, err := db.Admin.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, name := range []string{"nobody", "viewerAcme", "editorAcme", "adminAcme", "editorGlobex", "target", "Acme", "Globex"} {
		var id int64
		err := db.Admin.QueryRow(ctx,
			"select id from app.users where subject = $1 union all select id from app.orgs where name = $1", name).Scan(&id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ids[name] = id
	}

	st, err := store.Open(ctx, db.AppURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	srv := httptest.NewServer(testIdentity(api.NewHandler(st)))
	t.Cleanup(srv.Close)
	app := appv1connect.NewAppServiceClient(srv.Client(), srv.URL)
	access := accessv1connect.NewAccessServiceClient(srv.Client(), srv.URL)

	var visible []string // orgs seen by the last List* call
	calls := map[string]call{
		"WhoAmI": {"app.v1.AppService.WhoAmI", func(ctx context.Context, u string) error {
			_, err := app.WhoAmI(ctx, as(u, ids, &appv1.WhoAmIRequest{}))
			return err
		}},
		"ListProjects": {"app.v1.AppService.ListProjects", func(ctx context.Context, u string) error {
			res, err := app.ListProjects(ctx, as(u, ids, &appv1.ListProjectsRequest{}))
			visible = nil
			if err != nil {
				return err
			}
			for _, p := range res.Msg.GetProjects() {
				if !slices.Contains(visible, p.GetOrgName()) {
					visible = append(visible, p.GetOrgName())
				}
			}
			return nil
		}},
		"ListRoles": {"access.v1.AccessService.ListRoles", func(ctx context.Context, u string) error {
			_, err := access.ListRoles(ctx, as(u, ids, &accessv1.ListRolesRequest{}))
			return err
		}},
	}
	for _, org := range []string{"Acme", "Globex"} {
		calls["CreateProject in "+org] = call{"app.v1.AppService.CreateProject", func(ctx context.Context, u string) error {
			_, err := app.CreateProject(ctx, as(u, ids, &appv1.CreateProjectRequest{OrgId: ids[org], Name: "by " + u}))
			return err
		}}
		calls["UpdateProject in "+org] = call{"app.v1.AppService.UpdateProject", func(ctx context.Context, u string) error {
			var id, version int64
			if err := db.Admin.QueryRow(ctx, "select id, version from app.projects where name = $1", org+" roadmap").Scan(&id, &version); err != nil {
				return err
			}
			_, err := app.UpdateProject(ctx, as(u, ids, &appv1.UpdateProjectRequest{Id: id, Version: version, Name: org + " roadmap"}))
			return err
		}}
		calls["ListMembers of "+org] = call{"access.v1.AccessService.ListMembers", func(ctx context.Context, u string) error {
			_, err := access.ListMembers(ctx, as(u, ids, &accessv1.ListMembersRequest{OrgId: ids[org]}))
			return err
		}}
		calls["GrantRole editor in "+org] = call{"access.v1.AccessService.GrantRole", func(ctx context.Context, u string) error {
			_, err := access.GrantRole(ctx, as(u, ids, &accessv1.GrantRoleRequest{OrgId: ids[org], Email: "target@example.test", Role: "editor"}))
			return err
		}}
		calls["RevokeRole viewer in "+org] = call{"access.v1.AccessService.RevokeRole", func(ctx context.Context, u string) error {
			_, err := access.RevokeRole(ctx, as(u, ids, &accessv1.RevokeRoleRequest{OrgId: ids[org], UserId: ids["target"], Role: "viewer"}))
			return err
		}}
		calls["ListGroupMappings of "+org] = call{"access.v1.AccessService.ListGroupMappings", func(ctx context.Context, u string) error {
			_, err := access.ListGroupMappings(ctx, as(u, ids, &accessv1.ListGroupMappingsRequest{OrgId: ids[org]}))
			return err
		}}
		calls["AddGroupMapping in "+org] = call{"access.v1.AccessService.AddGroupMapping", func(ctx context.Context, u string) error {
			_, err := access.AddGroupMapping(ctx, as(u, ids, &accessv1.AddGroupMappingRequest{OrgId: ids[org], GroupId: "matrix-group-" + u, Role: "viewer"}))
			return err
		}}
		calls["RemoveGroupMapping in "+org] = call{"access.v1.AccessService.RemoveGroupMapping", func(ctx context.Context, u string) error {
			_, err := access.RemoveGroupMapping(ctx, as(u, ids, &accessv1.RemoveGroupMappingRequest{OrgId: ids[org], GroupId: "matrix-group", Role: "viewer"}))
			return err
		}}
	}

	// scaffold: calls above this line

	personas, rows := readMatrix(t)

	covered := map[string]bool{}
	for _, r := range rows {
		c, found := calls[r.action]
		if !found {
			t.Fatalf("%s: row %q has no call in matrix_test.go", matrixFile, r.action)
		}
		covered[c.method] = true
	}
	for _, md := range appMethods(t) {
		if !covered[string(md.FullName())] {
			t.Errorf("%s has no row in %s", md.FullName(), matrixFile)
		}
	}

	// Before each persona the rows that revoke and remove act on exist, so a "deny" comes
	// from the guards and not from a missing row.
	revokable := `
		insert into app.role_assignments (user_id, role_code, org_id)
		select u.id, 'viewer', o.id from app.users u, app.orgs o where u.subject = 'target' and o.name = 'Acme'
		on conflict do nothing;
		insert into app.idp_group_role_mappings (issuer, group_id, role_code, org_id)
		select 'test', 'matrix-group', 'viewer', id from app.orgs where name = 'Acme'
		on conflict do nothing;`

	for i, persona := range personas {
		user := persona
		if persona == "anonymous" {
			user = ""
		}
		t.Run(persona, func(t *testing.T) {
			if _, err := db.Admin.Exec(ctx, revokable); err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				want, wantOrgs := parseCell(t, r.cells[i])
				expect(t, r.action, calls[r.action].do(ctx, user), want)
				if wantOrgs != nil && !slices.Equal(visible, wantOrgs) {
					t.Errorf("%s: sees orgs %v, want %v", r.action, visible, wantOrgs)
				}
			}
		})
	}

	t.Run("invalid input", func(t *testing.T) {
		_, err := app.CreateProject(ctx, as("editorAcme", ids, &appv1.CreateProjectRequest{OrgId: ids["Acme"], Name: "  "}))
		expect(t, "CreateProject with blank name", err, connect.CodeInvalidArgument)
	})

	t.Run("stale version is aborted, not written", func(t *testing.T) {
		var id, v int64
		if err := db.Admin.QueryRow(ctx, "select id, version from app.projects where name = 'Acme roadmap'").Scan(&id, &v); err != nil {
			t.Fatal(err)
		}
		rename := func(user string, version int64, name string) (*connect.Response[appv1.UpdateProjectResponse], error) {
			return app.UpdateProject(ctx, as(user, ids, &appv1.UpdateProjectRequest{Id: id, Version: version, Name: name}))
		}
		res, err := rename("editorAcme", v, "Acme roadmap 2")
		if err != nil {
			t.Fatal(err)
		}
		if res.Msg.GetVersion() != v+1 {
			t.Errorf("version after rename = %d, want %d", res.Msg.GetVersion(), v+1)
		}
		_, err = rename("adminAcme", v, "lost update")
		expect(t, "UpdateProject with the version read before the other rename", err, connect.CodeAborted)
		// Not visible (or not writable) stays permission denied, even with a stale version.
		_, err = rename("editorGlobex", v, "x")
		expect(t, "UpdateProject of an invisible project", err, denied)
		_, err = rename("editorAcme", v+1, "  ")
		expect(t, "UpdateProject with blank name", err, connect.CodeInvalidArgument)

		// Readable but not writable (viewer here, editor elsewhere): denied, not aborted.
		grant := "insert into app.role_assignments (user_id, role_code, org_id) values ($1, 'viewer', $2)"
		if _, err := db.Admin.Exec(ctx, grant, ids["editorGlobex"], ids["Acme"]); err != nil {
			t.Fatal(err)
		}
		_, err = rename("editorGlobex", v+1, "x")
		expect(t, "UpdateProject by a viewer of the org", err, denied)
		_, err = rename("editorGlobex", v, "x")
		expect(t, "UpdateProject by a viewer of the org with a stale version", err, denied)

		var name string
		if err := db.Admin.QueryRow(ctx, "select name from app.projects where id = $1", id).Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name != "Acme roadmap 2" {
			t.Errorf("name = %q, want the first rename only", name)
		}
	})

	t.Run("a violated constraint arrives at its field, without database details", func(t *testing.T) {
		atField := func(call string, err error, field, message string) {
			t.Helper()
			got := fieldViolations(t, call, err)
			if want := map[string]string{field: message}; !maps.Equal(got, want) {
				t.Errorf("%s: violations %v, want %v", call, got, want)
			}
		}
		const dup = "a project with this name already exists"
		_, err := app.CreateProject(ctx, as("editorGlobex", ids, &appv1.CreateProjectRequest{OrgId: ids["Globex"], Name: " Globex roadmap "}))
		atField("CreateProject with a taken name", err, "name", dup)
		// The same name in another org is fine.
		created, err := app.CreateProject(ctx, as("editorAcme", ids, &appv1.CreateProjectRequest{OrgId: ids["Acme"], Name: "Globex roadmap"}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.CreateProject(ctx, as("editorAcme", ids, &appv1.CreateProjectRequest{OrgId: ids["Acme"], Name: "taken"})); err != nil {
			t.Fatal(err)
		}
		_, err = app.UpdateProject(ctx, as("editorAcme", ids, &appv1.UpdateProjectRequest{Id: created.Msg.GetId(), Version: 1, Name: "taken"}))
		atField("UpdateProject to a taken name", err, "name", dup)
		_, err = access.GrantRole(ctx, as("adminAcme", ids, &accessv1.GrantRoleRequest{OrgId: ids["Acme"], Email: "target@example.test", Role: "no_such_role"}))
		atField("GrantRole of an unknown role", err, "role", "no such role")
		_, err = access.AddGroupMapping(ctx, as("adminAcme", ids, &accessv1.AddGroupMappingRequest{OrgId: ids["Acme"], GroupId: "g", Role: "no_such_role"}))
		atField("AddGroupMapping of an unknown role", err, "role", "no such role")
	})

	t.Run("members filter by subject or display name, ignoring case", func(t *testing.T) {
		res, err := access.ListMembers(ctx, as("adminAcme", ids, &accessv1.ListMembersRequest{OrgId: ids["Acme"], Query: "VIEWER"}))
		if err != nil {
			t.Fatal(err)
		}
		if m := res.Msg.GetMembers(); len(m) != 1 || m[0].GetSubject() != "viewerAcme" {
			t.Errorf("got %v, want viewerAcme only", m)
		}
	})

	t.Run("disabled user is locked out on the next request", func(t *testing.T) {
		disable := "update app.users set disabled_at = case when $2 then now() end where id = $1"
		if _, err := db.Admin.Exec(ctx, disable, ids["editorAcme"], true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Admin.Exec(ctx, disable, ids["editorAcme"], false) })
		_, err := app.WhoAmI(ctx, as("editorAcme", ids, &appv1.WhoAmIRequest{}))
		expect(t, "WhoAmI of a disabled user", err, unauth)
		_, err = app.ListProjects(ctx, as("editorAcme", ids, &appv1.ListProjectsRequest{}))
		expect(t, "ListProjects of a disabled user", err, denied)
	})

	t.Run("audit records the actor", func(t *testing.T) {
		for _, q := range []struct{ table, filter, actor string }{
			{"projects", "new ->> 'name' = 'by editorAcme'", "editorAcme"},
			{"role_assignments", "new ->> 'user_id' = '" + strconv.FormatInt(ids["target"], 10) + "' and new ->> 'role_code' = 'editor'", "adminAcme"},
		} {
			var actor int64
			err := db.Admin.QueryRow(ctx, "select actor_id from app.audit_log where table_name = $1 and op = 'INSERT' and "+
				q.filter+" order by id limit 1", q.table).Scan(&actor)
			if err != nil {
				t.Fatalf("%s: %v", q.table, err)
			}
			if actor != ids[q.actor] {
				t.Errorf("%s: audit actor = %d, want %d (%s)", q.table, actor, ids[q.actor], q.actor)
			}
		}
	})
}

type matrixRow struct {
	action string
	cells  []string
}

// readMatrix parses the table whose header starts with "| Action" in docs/access-matrix.md.
func readMatrix(t *testing.T) (personas []string, rows []matrixRow) {
	t.Helper()
	f, err := os.Open(matrixFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	inTable := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		switch {
		case cells[0] == "Action":
			personas, inTable = cells[1:], true
		case !inTable || strings.HasPrefix(cells[0], "---"):
		case len(cells) != len(personas)+1:
			t.Fatalf("%s: row %q has %d cells for %d personas", matrixFile, cells[0], len(cells)-1, len(personas))
		default:
			rows = append(rows, matrixRow{action: cells[0], cells: cells[1:]})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s: no matrix table found", matrixFile)
	}
	return personas, rows
}

// fieldViolations is field -> message of an "invalid input" error; anything else fails the test.
func fieldViolations(t *testing.T, call string, err error) map[string]string {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument || ce.Message() != "invalid input" {
		t.Fatalf("%s: got %v, want invalid input", call, err)
	}
	got := map[string]string{}
	for _, d := range ce.Details() {
		if v, _ := d.Value(); v != nil {
			for _, x := range v.(*validatepb.Violations).GetViolations() {
				got[protovalidate.FieldPathString(x.GetField())] = x.GetMessage()
			}
		}
	}
	return got
}

func parseCell(t *testing.T, cell string) (connect.Code, []string) {
	t.Helper()
	switch {
	case cell == "allow":
		return ok, nil
	case strings.HasPrefix(cell, "allow:"):
		var orgs []string
		for o := range strings.SplitSeq(strings.TrimPrefix(cell, "allow:"), ",") {
			orgs = append(orgs, strings.TrimSpace(o))
		}
		return ok, orgs
	case cell == "deny":
		return denied, nil
	case cell == "sign-in":
		return unauth, nil
	}
	t.Fatalf("%s: unknown cell %q (allow, allow: <orgs>, deny, sign-in)", matrixFile, cell)
	return 0, nil
}

// testIdentity replaces the session middleware: the test names the user in a header.
func testIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, err := strconv.ParseInt(r.Header.Get("X-Test-User"), 10, 64); err == nil {
			r = r.WithContext(authz.WithUser(r.Context(), id))
		}
		next.ServeHTTP(w, r)
	})
}

func as[T any](user string, ids map[string]int64, msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if user != "" {
		req.Header().Set("X-Test-User", strconv.FormatInt(ids[user], 10))
	}
	return req
}

func expect(t *testing.T, call string, err error, want connect.Code) {
	t.Helper()
	got := ok
	if err != nil {
		got = connect.CodeOf(err)
	}
	if got != want {
		t.Errorf("%s: got %v, want %v (err: %v)", call, got, want, err)
	}
}
