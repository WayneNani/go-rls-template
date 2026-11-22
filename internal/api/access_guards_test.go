package api_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"testing"

	"connectrpc.com/connect"

	accessv1 "example.com/starter/gen/access/v1"
	"example.com/starter/gen/access/v1/accessv1connect"
	appv1 "example.com/starter/gen/app/v1"
	"example.com/starter/gen/app/v1/appv1connect"
	"example.com/starter/internal/api"
	"example.com/starter/internal/store"
	dbq "example.com/starter/internal/store/db"
	"example.com/starter/internal/testdb"
)

// The guards of migration 00004 that the access matrix cannot show.
// "gatekeeper" is a test-only role that may manage access but cannot read projects,
// so it shows the no-escalation rule.
func TestAccessGuards(t *testing.T) {
	ctx := context.Background()
	db := testdb.New(t)
	_, err := db.Admin.Exec(ctx, `
		insert into app.roles (code) values ('gatekeeper');
		insert into app.role_privileges (role_code, privilege_code) values ('gatekeeper', 'org.read'), ('gatekeeper', 'access.manage');
		insert into app.orgs (name) values ('Acme'), ('Globex');
		insert into app.users (issuer, subject, email) values
		  ('test', 'admin', 'admin@example.test'), ('test', 'gatekeeper', 'gate@example.test'),
		  ('test', 'member', 'member@example.test'), ('test', 'idpMember', 'idp@example.test'),
		  ('test', 'target', 'target@example.test'),
		  ('test', 'twin1', 'twin@example.test'), ('test', 'twin2', 'TWIN@example.test'),
		  ('other-idp', 'stranger', 'stranger@example.test');
		insert into app.role_assignments (user_id, role_code, org_id, source)
		select u.id, v.role, o.id, v.source
		  from (values ('admin', 'admin', 'local'), ('gatekeeper', 'gatekeeper', 'local'),
		               ('member', 'viewer', 'local'), ('idpMember', 'viewer', 'idp')) v (subject, role, source)
		  join app.users u on u.subject = v.subject
		  join app.orgs o on o.name = 'Acme';
		-- idpMember holds viewer through group acme-viewers; admin is in group admins-own
		update app.users set idp_groups = '{acme-viewers}' where subject = 'idpMember';
		update app.users set idp_groups = '{admins-own}' where subject = 'admin';
		insert into app.idp_group_role_mappings (issuer, group_id, role_code, org_id)
		select 'test', 'acme-viewers', 'viewer', id from app.orgs where name = 'Acme';`)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, name := range []string{"admin", "gatekeeper", "member", "idpMember", "target", "stranger", "Acme", "Globex"} {
		var id int64
		if err := db.Admin.QueryRow(ctx,
			"select id from app.users where subject = $1 union all select id from app.orgs where name = $1", name).Scan(&id); err != nil {
			t.Fatal(err)
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
	c := accessv1connect.NewAccessServiceClient(srv.Client(), srv.URL)
	acme := ids["Acme"]

	grant := func(by, email, role string, org int64) error {
		_, err := c.GrantRole(ctx, as(by, ids, &accessv1.GrantRoleRequest{OrgId: org, Email: email, Role: role}))
		return err
	}
	revoke := func(by, user, role string) error {
		_, err := c.RevokeRole(ctx, as(by, ids, &accessv1.RevokeRoleRequest{OrgId: acme, UserId: ids[user], Role: role}))
		return err
	}
	addMapping := func(by, role string) error {
		_, err := c.AddGroupMapping(ctx, as(by, ids, &accessv1.AddGroupMappingRequest{OrgId: acme, GroupId: "g-" + role, Role: role}))
		return err
	}

	for _, tc := range []struct {
		name string
		err  error
		want connect.Code
	}{
		{"no grant to yourself", grant("admin", "admin@example.test", "viewer", acme), denied},
		{"no revoke of your own role", revoke("admin", "admin", "admin"), denied},
		{"no grant beyond your privileges", grant("gatekeeper", "target@example.test", "viewer", acme), denied},
		{"grant within your privileges", grant("gatekeeper", "target@example.test", "gatekeeper", acme), ok},
		{"no revoke beyond your privileges", revoke("gatekeeper", "member", "viewer"), denied},
		{"IdP roles are read-only", revoke("admin", "idpMember", "viewer"), denied},
		{"only in orgs you manage", grant("admin", "target@example.test", "viewer", ids["Globex"]), denied},
		{"email lookup is case-insensitive", grant("admin", "MEMBER@example.test", "editor", acme), ok},
		{"unknown email", grant("admin", "nobody@example.test", "viewer", acme), connect.CodeNotFound},
		{"ambiguous email is refused", grant("admin", "twin@example.test", "viewer", acme), connect.CodeInvalidArgument},
		{"users of another IdP are not found", grant("admin", "stranger@example.test", "viewer", acme), connect.CodeNotFound},
		{"no mapping beyond your privileges", addMapping("gatekeeper", "editor"), denied},
		{"mapping within your privileges", addMapping("gatekeeper", "gatekeeper"), ok},
		{"a member cannot manage access", grant("member", "target@example.test", "viewer", acme), denied},
		{"no mapping for a group you are in", func() error {
			_, err := c.AddGroupMapping(ctx, as("admin", ids, &accessv1.AddGroupMappingRequest{OrgId: acme, GroupId: "admins-own", Role: "admin"}))
			return err
		}(), denied},
		{"granting a role held through the IdP says so", grant("admin", "idp@example.test", "viewer", acme), connect.CodeAlreadyExists},
	} {
		t.Run(tc.name, func(t *testing.T) { expect(t, tc.name, tc.err, tc.want) })
	}

	t.Run("the database refuses users of another IdP, also without the email lookup", func(t *testing.T) {
		err := st.WithUser(ctx, ids["admin"], func(q *dbq.Queries) error {
			_, err := q.GrantRole(ctx, dbq.GrantRoleParams{UserID: ids["stranger"], RoleCode: "viewer", OrgID: acme})
			return err
		})
		if !errors.Is(err, store.ErrForbidden) {
			t.Errorf("grant to a user of another IdP: err = %v, want forbidden", err)
		}
	})

	t.Run("WhoAmI shows only your own roles", func(t *testing.T) {
		res, err := appv1connect.NewAppServiceClient(srv.Client(), srv.URL).WhoAmI(ctx, as("admin", ids, &appv1.WhoAmIRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if roles := res.Msg.GetRoles(); len(roles) != 1 || roles[0].GetRole() != "admin" || res.Msg.GetUserId() != ids["admin"] {
			t.Errorf("WhoAmI(admin) = user %d, roles %v", res.Msg.GetUserId(), roles)
		}
	})

	t.Run("mappings use the caller's issuer", func(t *testing.T) {
		var issuer string
		if err := db.Admin.QueryRow(ctx, "select issuer from app.idp_group_role_mappings where group_id = 'g-gatekeeper'").Scan(&issuer); err != nil {
			t.Fatal(err)
		}
		if issuer != "test" {
			t.Errorf("mapping issuer = %q, want the caller's issuer %q", issuer, "test")
		}
	})

	t.Run("members list shows sources and pages", func(t *testing.T) {
		seen := map[string]string{}
		token, pages := "", 0
		for {
			res, err := c.ListMembers(ctx, as("admin", ids, &accessv1.ListMembersRequest{OrgId: acme, PageSize: 2, PageToken: token}))
			if err != nil {
				t.Fatal(err)
			}
			pages++
			for _, m := range res.Msg.GetMembers() {
				for _, r := range m.GetRoles() {
					seen[m.GetSubject()+":"+r.GetRole()] = r.GetSource()
				}
			}
			if token = res.Msg.GetNextPageToken(); token == "" {
				break
			}
		}
		if seen["idpMember:viewer"] != "idp" || seen["member:viewer"] != "local" || seen["target:gatekeeper"] != "local" {
			t.Errorf("members = %v", seen)
		}
		if _, found := seen["twin1:viewer"]; found || pages < 2 {
			t.Errorf("members without a role in Acme must not appear; pages = %d", pages)
		}
	})

	t.Run("mappings list pages", func(t *testing.T) {
		var seen []string
		token := ""
		for {
			res, err := c.ListGroupMappings(ctx, as("admin", ids, &accessv1.ListGroupMappingsRequest{OrgId: acme, PageSize: 1, PageToken: token}))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range res.Msg.GetMappings() {
				seen = append(seen, m.GetGroupId()+":"+m.GetRole())
			}
			if token = res.Msg.GetNextPageToken(); token == "" {
				break
			}
		}
		if want := []string{"acme-viewers:viewer", "g-gatekeeper:gatekeeper"}; !slices.Equal(seen, want) {
			t.Errorf("mappings = %v, want %v, one per page", seen, want)
		}
	})

	t.Run("removing a mapping removes the roles it backed", func(t *testing.T) {
		_, err := c.RemoveGroupMapping(ctx, as("admin", ids, &accessv1.RemoveGroupMappingRequest{OrgId: acme, GroupId: "acme-viewers", Role: "viewer"}))
		if err != nil {
			t.Fatal(err)
		}
		var left int
		if err := db.Admin.QueryRow(ctx, "select count(*) from app.role_assignments where user_id = $1 and source = 'idp'",
			ids["idpMember"]).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("idpMember still holds %d IdP roles after the mapping was removed", left)
		}
	})
}
