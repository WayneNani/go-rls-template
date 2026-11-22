package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"example.com/starter/internal/store"
	"example.com/starter/internal/store/db"
	"example.com/starter/internal/testdb"
)

// Guards of migration 00005: disabled users and audited reads of sensitive columns.
func TestMigration5Guards(t *testing.T) {
	ctx := context.Background()
	tdb := testdb.New(t)
	_, err := tdb.Admin.Exec(ctx, `
		insert into app.orgs (name) values ('Acme');
		insert into app.users (issuer, subject, email) values
		  ('test', 'manager', 'manager@example.test'), ('test', 'member', 'member@example.test'),
		  ('test', 'outsider', 'outsider@example.test');
		insert into app.role_assignments (user_id, role_code, org_id)
		select u.id, v.role, o.id from (values ('manager', 'admin'), ('member', 'viewer')) v (subject, role)
		  join app.users u on u.subject = v.subject, app.orgs o;`)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, s := range []string{"manager", "member", "outsider"} {
		var id int64
		if err := tdb.Admin.QueryRow(ctx, "select id from app.users where subject = $1", s).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[s] = id
	}
	st, err := store.Open(ctx, tdb.AppURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	readCount := func() (n int) {
		t.Helper()
		if err := tdb.Admin.QueryRow(ctx, "select count(*) from app.audit_log where op = 'READ'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	emails := func(user string, of ...string) (got []string) {
		t.Helper()
		var userIDs []int64
		for _, o := range of {
			userIDs = append(userIDs, ids[o])
		}
		err := st.WithUser(ctx, ids[user], func(q *db.Queries) error {
			rows, err := q.UserEmails(ctx, userIDs)
			for _, r := range rows {
				got = append(got, r.Email)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("app_rw cannot select a sensitive column directly", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, tdb.AppURL)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		var email *string
		err = conn.QueryRow(ctx, "select email from app.users limit 1").Scan(&email)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("select email as app_rw: err = %v, want permission denied", err)
		}
	})

	t.Run("own email: returned, not audited", func(t *testing.T) {
		before := readCount()
		if got := emails("member", "member"); !slices.Equal(got, []string{"member@example.test"}) {
			t.Errorf("own email = %v", got)
		}
		if readCount() != before {
			t.Error("reading your own email wrote an audit row")
		}
	})

	t.Run("others' emails: only what the caller manages, one audit row naming the ids", func(t *testing.T) {
		before := readCount()
		got := emails("manager", "member", "outsider", "manager")
		if !slices.Equal(got, []string{"manager@example.test", "member@example.test"}) {
			t.Errorf("manager sees %v, want own and member's (outsider has no role in Acme)", got)
		}
		if readCount() != before+1 {
			t.Fatalf("audit READ rows: %d new, want 1", readCount()-before)
		}
		var actor int64
		var readIDs []int64
		err := tdb.Admin.QueryRow(ctx, `select actor_id, array(select jsonb_array_elements_text(row_key -> 'ids')::bigint)
		                                  from app.audit_log where op = 'READ' order by id desc limit 1`).Scan(&actor, &readIDs)
		if err != nil {
			t.Fatal(err)
		}
		if actor != ids["manager"] || !slices.Equal(readIDs, []int64{ids["member"]}) {
			t.Errorf("audit row: actor %d ids %v, want %d [%d]", actor, readIDs, ids["manager"], ids["member"])
		}
		if got := emails("member", "manager"); len(got) != 0 {
			t.Errorf("a viewer reads others' emails: %v", got)
		}
	})

	t.Run("disabled user is nobody on the next request and cannot sign in", func(t *testing.T) {
		if _, err := tdb.Admin.Exec(ctx, "update app.users set disabled_at = now() where id = $1", ids["manager"]); err != nil {
			t.Fatal(err)
		}
		if ok, err := st.HasPrivilege(ctx, ids["manager"], "org.read"); err != nil || ok {
			t.Errorf("disabled admin holds org.read: %v (err %v)", ok, err)
		}
		err := st.WithUser(ctx, ids["manager"], func(q *db.Queries) error { _, err := q.CurrentUser(ctx); return err })
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CurrentUser of a disabled user: err = %v, want ErrNotFound", err)
		}
		err = st.AsLogin(ctx, func(q *db.Queries) error {
			_, err := q.UpsertLoginUser(ctx, db.UpsertLoginUserParams{Issuer: "test", Subject: "manager"})
			return err
		})
		if !errors.Is(err, store.ErrUserDisabled) {
			t.Errorf("sign-in of a disabled user: err = %v, want ErrUserDisabled", err)
		}
		// Others are unaffected.
		if ok, err := st.HasPrivilege(ctx, ids["member"], "org.read"); err != nil || !ok {
			t.Errorf("member lost org.read: %v (err %v)", ok, err)
		}
	})
}
