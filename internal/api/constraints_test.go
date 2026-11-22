package api_test

import (
	"context"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"example.com/starter/internal/api"
	"example.com/starter/internal/testdb"
)

// Constraints app_rw can violate: on tables it may insert into or update, and foreign keys to
// tables it may delete from or update. Unique indexes count like unique constraints (a
// violation names the index). Not-null violations name a column, not a constraint; proto rules
// mirror them. Tables written only by SECURITY DEFINER functions handle conflicts there.
const triggerableConstraints = `
	select c.conname from pg_constraint c
	 where c.connamespace = 'app'::regnamespace and c.contype <> 'n'
	   and (has_table_privilege('app_rw', c.conrelid, 'INSERT') or has_any_column_privilege('app_rw', c.conrelid, 'UPDATE')
	        or (c.contype = 'f' and (has_table_privilege('app_rw', c.confrelid, 'DELETE')
	                                 or has_any_column_privilege('app_rw', c.confrelid, 'UPDATE'))))
	union
	select i.indexrelid::regclass::text from pg_index i join pg_class t on t.oid = i.indrelid
	 where t.relnamespace = 'app'::regnamespace and i.indisunique
	   and not exists (select 1 from pg_constraint c where c.conindid = i.indexrelid)
	   and (has_table_privilege('app_rw', t.oid, 'INSERT') or has_any_column_privilege('app_rw', t.oid, 'UPDATE'))`

const allConstraints = `
	select conname from pg_constraint where connamespace = 'app'::regnamespace
	union
	select i.indexrelid::regclass::text from pg_index i join pg_class t on t.oid = i.indrelid
	 where t.relnamespace = 'app'::regnamespace and i.indisunique`

// A violated constraint reaches the caller at a request field (constraintFields in
// constraints.go) or is listed as not user-facing with a reason; no mapping names a constraint
// or a field that does not exist (any more).
func TestEveryConstraintIsMapped(t *testing.T) {
	db := testdb.New(t)
	names := func(sql string) map[string]bool {
		rows, err := db.Admin.Query(context.Background(), sql)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[n] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	fields, notUserFacing := api.MappedConstraints()

	for name := range names(triggerableConstraints) {
		if _, ok := fields[name]; !ok && notUserFacing[name] == "" {
			t.Errorf("constraint %s: map it to a request field in constraintFields, or list it in constraintsNotUserFacing with a reason", name)
		}
	}
	existing := names(allConstraints)
	requestFieldNames := map[string]bool{}
	requestFields(t, func(fd protoreflect.FieldDescriptor) { requestFieldNames[string(fd.Name())] = true })
	for name, field := range fields {
		if !existing[name] {
			t.Errorf("constraintFields: no constraint %s in schema app", name)
		}
		if !requestFieldNames[field] {
			t.Errorf("constraintFields: %s maps to %q, which no request message has", name, field)
		}
		if notUserFacing[name] != "" {
			t.Errorf("constraint %s is mapped and listed as not user-facing", name)
		}
	}
	for name := range notUserFacing {
		if !existing[name] {
			t.Errorf("constraintsNotUserFacing: no constraint %s in schema app", name)
		}
	}
}
