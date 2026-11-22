-- Guards Oracle APEX has built in and this template lacked:
--   * lost-update protection: a row version every writer must send back (APEX: checksum on save)
--   * lock-out at once: a disabled user is nobody on the very next request and cannot sign in
--   * read audit: sensitive columns are not selectable by app_rw; one SECURITY DEFINER
--     function reads them and writes an audit row per call (APEX: activity log)

-- +goose Up
-- Bounded waits for the table locks below (squawk); local to goose's transaction.
set local lock_timeout = '5s';
set local statement_timeout = '60s';

-- Lost updates. The database bumps the version on every update, so no query can forget it;
-- writers lock the row, compare the version the caller read, then update.
-- invariants_test.go: every table app_rw may update has a version column.
alter table app.projects add column version bigint not null default 1;

-- +goose StatementBegin
create function app.bump_version() returns trigger
language plpgsql
as $$ begin new.version := old.version + 1; return new; end $$;
-- +goose StatementEnd

create trigger projects_version before update on app.projects
  for each row execute function app.bump_version();

-- Disabled users. Set by ops (SQL now, SCIM later), never through the API: users are
-- global across orgs, so no org admin may lock someone out everywhere.
alter table app.users add column disabled_at timestamptz;

-- Every policy and has_privilege go through this, so a disabled user is nobody at once,
-- whatever session they still hold. Definer: reads app.users without its RLS policy
-- (which calls this function).
-- +goose StatementBegin
create or replace function app.current_user_id() returns bigint
language sql stable security definer set search_path = app, pg_temp
as $$
  select u.id from app.users u
   where u.id = nullif(current_setting('app.user_id', true), '')::bigint
     and u.disabled_at is null
$$;
-- +goose StatementEnd

-- Sign-in of a disabled user fails with SQLSTATE P0004 (store.ErrUserDisabled).
-- +goose StatementBegin
create or replace function app.upsert_login_user(p_issuer text, p_subject text, p_email text, p_display_name text)
returns bigint
language plpgsql security definer set search_path = app, pg_temp
as $$
declare
  v_id       bigint;
  v_disabled timestamptz;
begin
  insert into app.users as u (issuer, subject, email, display_name)
  values (p_issuer, p_subject, p_email, p_display_name)
  on conflict (issuer, subject) do update
     set email        = coalesce(excluded.email, u.email),
         display_name = coalesce(excluded.display_name, u.display_name)
  returning u.id, u.disabled_at into v_id, v_disabled;
  if v_disabled is not null then
    raise exception 'user is disabled' using errcode = 'P0004';
  end if;
  return v_id;
end
$$;
-- +goose StatementEnd

-- Same as 00003 plus the failure code 'disabled'.
-- +goose StatementBegin
create or replace function app.record_auth_event(p_op text, p_user_id bigint, p_issuer text, p_subject text,
                                                 p_detail text, p_client_ip inet)
returns void
language sql security definer set search_path = app, pg_temp
as $$
  insert into app.audit_log (actor_id, table_name, op, row_key, new)
  select p_user_id, 'auth', p_op, null,
         jsonb_strip_nulls(jsonb_build_object(
           'issuer', p_issuer, 'subject', p_subject, 'client_ip', host(p_client_ip),
           'detail', case when p_detail in ('idp_error', 'state', 'code_exchange', 'id_token', 'claims',
                                            'user_sync', 'session', 'login_transaction', 'disabled')
                          then p_detail
                          when p_detail is not null then 'other' end))
   where p_op in ('LOGIN', 'LOGIN_FAILED', 'LOGOUT')
$$;
-- +goose StatementEnd

-- Sensitive columns: marked by a comment starting with 'sensitive:', never selectable by
-- app_rw (invariants_test.go). app_rw gets column grants only, so a new users column stays
-- unreadable until granted.
comment on column app.users.email is 'sensitive: read only through app.user_emails (audited)';
revoke select on app.users from app_rw;
grant select (id, issuer, subject, display_name, idp_groups) on app.users to app_rw;

-- The emails the caller may see (their own, or members of orgs they manage, as the users
-- policy allows). Each call that returns someone else's email writes one audit row
-- (op READ, the ids). Reading your own (WhoAmI) is not logged: it discloses nothing.
-- +goose StatementBegin
create function app.user_emails(p_user_ids bigint[]) returns table (user_id bigint, email text)
language plpgsql security definer set search_path = app, pg_temp
as $$
#variable_conflict use_column
declare
  v_me     bigint := app.current_user_id();
  v_ids    bigint[];
  v_others bigint[];
begin
  select array_agg(u.id order by u.id) into v_ids
    from app.users u
   where u.id = any (p_user_ids)
     and (u.id = v_me
          or exists (select 1 from app.role_assignments ra
                      where ra.user_id = u.id and app.has_privilege('access.manage', ra.org_id)));
  v_others := array(select i from unnest(v_ids) i where i is distinct from v_me);
  if cardinality(v_others) > 0 then
    insert into app.audit_log (actor_id, table_name, op, row_key, new)
    values (v_me, 'users', 'READ', jsonb_build_object('ids', to_jsonb(v_others)),
            jsonb_build_object('columns', jsonb_build_array('email')));
  end if;
  return query select u.id, u.email from app.users u where u.id = any (v_ids) order by u.id;
end
$$;
-- +goose StatementEnd

grant execute on function app.user_emails(bigint[]) to app_rw;

-- +goose Down
revoke execute on function app.user_emails(bigint[]) from app_rw;
drop function app.user_emails(bigint[]);
revoke select (id, issuer, subject, display_name, idp_groups) on app.users from app_rw;
grant select on app.users to app_rw;
comment on column app.users.email is null;

-- +goose StatementBegin
create or replace function app.record_auth_event(p_op text, p_user_id bigint, p_issuer text, p_subject text,
                                                 p_detail text, p_client_ip inet)
returns void
language sql security definer set search_path = app, pg_temp
as $$
  insert into app.audit_log (actor_id, table_name, op, row_key, new)
  select p_user_id, 'auth', p_op, null,
         jsonb_strip_nulls(jsonb_build_object(
           'issuer', p_issuer, 'subject', p_subject, 'client_ip', host(p_client_ip),
           'detail', case when p_detail in ('idp_error', 'state', 'code_exchange', 'id_token', 'claims',
                                            'user_sync', 'session', 'login_transaction')
                          then p_detail
                          when p_detail is not null then 'other' end))
   where p_op in ('LOGIN', 'LOGIN_FAILED', 'LOGOUT')
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create or replace function app.upsert_login_user(p_issuer text, p_subject text, p_email text, p_display_name text)
returns bigint
language sql security definer set search_path = app, pg_temp
as $$
  insert into app.users as u (issuer, subject, email, display_name)
  values (p_issuer, p_subject, p_email, p_display_name)
  on conflict (issuer, subject) do update
     set email        = coalesce(excluded.email, u.email),
         display_name = coalesce(excluded.display_name, u.display_name)
  returning id
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create or replace function app.current_user_id() returns bigint
language sql stable security invoker
as $$ select nullif(current_setting('app.user_id', true), '')::bigint $$;
-- +goose StatementEnd

alter table app.users drop column disabled_at;
drop trigger projects_version on app.projects;
drop function app.bump_version();
alter table app.projects drop column version;
