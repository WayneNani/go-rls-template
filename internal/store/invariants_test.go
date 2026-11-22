package store_test

import (
	"context"
	"testing"

	"example.com/starter/internal/testdb"
)

// Each query lists violations of a database security rule; every one must return no rows.
var invariants = []struct{ name, sql string }{
	{"nothing lives outside schema app (an unqualified create lands in public)", `
		select n.nspname || '.' || c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
		 where n.nspname not in ('app', 'pg_catalog', 'information_schema', 'pg_toast')
		   and not (n.nspname = 'public' and c.relname like 'goose\_db\_version%') -- goose's own bookkeeping
		union all
		select n.nspname || '.' || p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
		 where n.nspname not in ('app', 'pg_catalog', 'information_schema')`},
	{"every table has RLS enabled and forced", `
		select c.relname from pg_class c
		 where c.relnamespace = 'app'::regnamespace and c.relkind in ('r', 'p')
		   and not (c.relrowsecurity and c.relforcerowsecurity)`},
	{"every view runs with the caller's rights", `
		select c.relname from pg_class c
		 where c.relnamespace = 'app'::regnamespace and c.relkind = 'v'
		   and not coalesce(c.reloptions @> '{security_invoker=true}', false)`},
	{"SECURITY DEFINER only on the allowlist, always with a fixed search_path", `
		select p.proname from pg_proc p
		 where p.pronamespace = 'app'::regnamespace and p.prosecdef
		   and (p.proname <> all (array['has_privilege', 'upsert_login_user', 'sync_idp_roles', 'audit', 'record_auth_event',
		                                'find_user_by_email', 'shares_my_issuer', 'drop_unbacked_idp_roles',
		                                -- current_user_id: reads app.users past its policy (which calls it) to drop disabled users
		                                -- user_emails: the only, audited way to sensitive columns
		                                'current_user_id', 'user_emails'])
		        -- one name, one function: an overload could hide a second, unreviewed body
		        or (select count(*) from pg_proc o where o.pronamespace = p.pronamespace and o.proname = p.proname) > 1
		        or not exists (select 1 from unnest(p.proconfig) c where c like 'search_path=%'))`},
	{"no function in app is executable by PUBLIC", `
		select p.proname from pg_proc p
		 where p.pronamespace = 'app'::regnamespace and has_function_privilege('public', p.oid, 'execute')`},
	{"every table is audited or deliberately exempt", `
		select c.relname from pg_class c
		 where c.relnamespace = 'app'::regnamespace and c.relkind in ('r', 'p')
		   -- exempt: catalog (changed only by reviewed migrations), sessions, the audit log itself
		   and c.relname <> all (array['privileges', 'roles', 'role_privileges', 'sessions', 'audit_log'])
		   -- enabled row triggers calling app.audit() that together cover insert (4), delete (8), update (16)
		   and coalesce((select bit_or(t.tgtype & 28) from pg_trigger t
		                  where t.tgrelid = c.oid and not t.tgisinternal and t.tgenabled in ('O', 'A')
		                    and t.tgfoid = 'app.audit'::regproc and (t.tgtype & 1) = 1), 0) <> 28`},
	{"admin holds every privilege any role holds (managers delegate within their own privileges)", `
		select distinct rp.privilege_code from app.role_privileges rp
		 where not exists (select 1 from app.role_privileges a
		                    where a.role_code = 'admin' and a.privilege_code = rp.privilege_code)`},
	{"audit log rejects update, delete and truncate", `
		select op from (values ('update', 16), ('delete', 8), ('truncate', 32)) v (op, bit)
		 where not exists (select 1 from pg_trigger t
		                    where t.tgrelid = 'app.audit_log'::regclass and t.tgenabled in ('O', 'A')
		                      and t.tgfoid = 'app.deny_truncate'::regproc and (t.tgtype & v.bit) <> 0)`},
	{"runtime role is not privileged", `
		select rolname from pg_roles
		 where rolname = 'app_rw' and (rolsuper or rolbypassrls or rolcreaterole or rolcreatedb)`},
	{"runtime role owns nothing", `
		select c.relname from pg_class c join pg_roles r on r.oid = c.relowner
		 where r.rolname = 'app_rw'
		union all
		select n.nspname from pg_namespace n join pg_roles r on r.oid = n.nspowner where r.rolname = 'app_rw'`},
	{"runtime role cannot touch the audit log", `
		select 'audit_log' where has_table_privilege('app_rw', 'app.audit_log', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`},
	{"runtime role changes roles and IdP mappings only by insert and delete (through the guard policies)", `
		select t from unnest(array['app.role_assignments', 'app.idp_group_role_mappings']) t
		 where has_table_privilege('app_rw', t, 'UPDATE,TRUNCATE')`},
	{"every table app_rw may update has a version column (lost-update protection, see UpdateProject)", `
		select c.relname from pg_class c
		 where c.relnamespace = 'app'::regnamespace and c.relkind in ('r', 'p')
		   and has_any_column_privilege('app_rw', c.oid, 'UPDATE')
		   -- exempt: sessions (written by scs, one writer per token)
		   and c.relname <> all (array['sessions'])
		   and not exists (select 1 from pg_attribute a
		                    where a.attrelid = c.oid and a.attname = 'version' and not a.attisdropped
		                      and a.atttypid = 'bigint'::regtype)`},
	{"no column marked 'sensitive:' is selectable by app_rw (read through an audited definer function)", `
		select c.relname || '.' || a.attname from pg_attribute a join pg_class c on c.oid = a.attrelid
		 where c.relnamespace = 'app'::regnamespace and a.attnum > 0 and not a.attisdropped
		   and col_description(c.oid, a.attnum) like 'sensitive:%'
		   and has_column_privilege('app_rw', c.oid, a.attnum, 'SELECT')`},
	{"known sensitive columns stay marked", `
		select v.t || '.' || v.c from (values ('users', 'email')) v (t, c)
		 where not exists (select 1 from pg_attribute a
		                    where a.attrelid = ('app.' || v.t)::regclass and a.attname = v.c
		                      and col_description(a.attrelid, a.attnum) like 'sensitive:%')`},
	{"runtime role has statement, lock and idle-in-transaction timeouts (dev/roles.sql; production too)", `
		select s from unnest(array['statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout']) s
		 where not exists (select 1 from pg_db_role_setting d, unnest(d.setconfig) c
		                    where d.setrole = 'app_rw'::regrole
		                      and d.setdatabase in (0, (select oid from pg_database where datname = current_database()))
		                      and split_part(c, '=', 1) = s and split_part(c, '=', 2) not in ('', '0'))`},
}

func TestDatabaseInvariants(t *testing.T) {
	db := testdb.New(t)
	for _, inv := range invariants {
		t.Run(inv.name, func(t *testing.T) {
			rows, err := db.Admin.Query(context.Background(), inv.sql)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var name string
				if err := rows.Scan(&name); err != nil {
					t.Fatal(err)
				}
				t.Errorf("violation: %s", name)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
		})
	}

	// Even a superuser cannot rewrite history (short of disabling the triggers).
	ctx := context.Background()
	if _, err := db.Admin.Exec(ctx, "insert into app.audit_log (table_name, op) values ('test', 'TEST')"); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"update app.audit_log set op = 'X'", "delete from app.audit_log", "truncate app.audit_log"} {
		if _, err := db.Admin.Exec(ctx, stmt); err == nil {
			t.Errorf("%s succeeded on the append-only audit log", stmt)
		}
	}
}
