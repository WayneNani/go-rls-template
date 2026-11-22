package api_test

import (
	"context"
	"net/http/httptest"
	"slices"
	"testing"

	"connectrpc.com/connect"

	appv1 "example.com/starter/gen/app/v1"
	"example.com/starter/gen/app/v1/appv1connect"
	"example.com/starter/internal/api"
	"example.com/starter/internal/store"
	"example.com/starter/internal/testdb"
)

func TestListProjectsPaging(t *testing.T) {
	ctx := context.Background()
	db := testdb.New(t)
	_, err := db.Admin.Exec(ctx, `
		insert into app.orgs (name) values ('Acme'), ('Globex');
		insert into app.users (issuer, subject) values ('test', 'viewer');
		insert into app.role_assignments (user_id, role_code, org_id)
		select u.id, 'viewer', o.id from app.users u, app.orgs o where o.name = 'Acme';
		-- five visible projects with the same timestamp (ties are broken by id), three hidden;
		-- the filter "ACME" matches three of the visible ones, interleaved with the others
		insert into app.projects (org_id, name, created_at)
		select o.id, case when n % 2 = 1 then o.name else 'Other' end || ' ' || n, '2026-01-01'
		  from app.orgs o, generate_series(1, 5) n where o.name = 'Acme' or n <= 3;`)
	if err != nil {
		t.Fatal(err)
	}
	var viewer int64
	if err := db.Admin.QueryRow(ctx, "select id from app.users where subject = 'viewer'").Scan(&viewer); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, db.AppURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	srv := httptest.NewServer(testIdentity(api.NewHandler(st)))
	t.Cleanup(srv.Close)
	client := appv1connect.NewAppServiceClient(srv.Client(), srv.URL)
	ids := map[string]int64{"viewer": viewer}

	list := func(query string) (names []string, pages int) {
		seen := map[int64]bool{}
		token := ""
		for {
			res, err := client.ListProjects(ctx, as("viewer", ids, &appv1.ListProjectsRequest{PageSize: 2, PageToken: token, Query: query}))
			if err != nil {
				t.Fatal(err)
			}
			pages++
			for _, p := range res.Msg.GetProjects() {
				if p.GetOrgName() != "Acme" || seen[p.GetId()] {
					t.Errorf("unexpected or repeated project %d (%s)", p.GetId(), p.GetOrgName())
				}
				seen[p.GetId()] = true
				names = append(names, p.GetName())
			}
			if token = res.Msg.GetNextPageToken(); token == "" {
				return names, pages
			}
		}
	}
	if names, pages := list(""); len(names) != 5 || pages != 3 {
		t.Errorf("got %v on %d pages, want 5 projects on 3", names, pages)
	}
	if names, pages := list(" ACME "); !slices.Equal(names, []string{"Acme 5", "Acme 3", "Acme 1"}) || pages != 2 {
		t.Errorf("filtered: got %v on %d pages, want [Acme 5 Acme 3 Acme 1] on 2", names, pages)
	}
	if names, _ := list("%"); len(names) != 0 {
		t.Errorf("%% is a literal in the filter, got %v", names)
	}

	_, err = client.ListProjects(ctx, as("viewer", ids, &appv1.ListProjectsRequest{PageToken: "not-a-token"}))
	expect(t, "ListProjects with forged token", err, connect.CodeInvalidArgument)
}
