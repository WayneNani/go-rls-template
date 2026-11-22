package store_test

import (
	"context"
	"slices"
	"testing"

	"example.com/starter/internal/store"
	"example.com/starter/internal/store/db"
	"example.com/starter/internal/testdb"
)

func TestAuthEventsAreAudited(t *testing.T) {
	ctx := context.Background()
	tdb := testdb.New(t)
	st, err := store.Open(ctx, tdb.AppURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	detail, subject, injected, disabled := "state", "mallory", "<script>alert(1)</script>", "disabled"
	for _, ev := range []db.RecordAuthEventParams{
		{Op: "LOGIN_FAILED", Detail: &detail},
		{Op: "LOGIN", Subject: &subject},
		{Op: "LOGIN_FAILED", Detail: &injected}, // caller text is not stored, only "other"
		{Op: "DROP TABLE", Subject: &subject},   // unknown ops are ignored, not stored
		{Op: "LOGIN_FAILED", Detail: &disabled}, // sign-in of a disabled user (store.ErrUserDisabled)
	} {
		if err := st.AsLogin(ctx, func(q *db.Queries) error { return q.RecordAuthEvent(ctx, ev) }); err != nil {
			t.Fatal(err)
		}
	}

	var ops []string
	rows, err := tdb.Admin.Query(ctx, "select op || coalesce(':' || (new ->> 'detail'), '') from app.audit_log where table_name = 'auth' order by id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var op string
		if err := rows.Scan(&op); err != nil {
			t.Fatal(err)
		}
		ops = append(ops, op)
	}
	want := []string{"LOGIN_FAILED:state", "LOGIN", "LOGIN_FAILED:other", "LOGIN_FAILED:disabled"}
	if !slices.Equal(ops, want) {
		t.Errorf("audited auth events = %v, want %v", ops, want)
	}
}
