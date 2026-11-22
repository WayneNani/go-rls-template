-- Runs as app_owner. The runtime role app_rw owns nothing and reaches data only
-- through RLS policies and the few SECURITY DEFINER functions allowlisted in
-- internal/store/invariants_test.go.

-- +goose Up
create schema app;

alter default privileges for role app_owner revoke execute on functions from public;

-- Catalog: what a role means. Versioned here, never edited in the UI.
create table app.privileges (code text primary key);
create table app.roles (code text primary key);
create table app.role_privileges (
  role_code      text not null references app.roles,
  privilege_code text not null references app.privileges,
  primary key (role_code, privilege_code)
);

insert into app.privileges (code) values ('org.read'), ('project.read'), ('project.write');
insert into app.roles (code) values ('viewer'), ('editor'), ('admin');
insert into app.role_privileges (role_code, privilege_code) values
  ('viewer', 'org.read'), ('viewer', 'project.read'),
  ('editor', 'org.read'), ('editor', 'project.read'), ('editor', 'project.write'),
  ('admin',  'org.read'), ('admin',  'project.read'), ('admin',  'project.write');

create table app.users (
  id           bigint generated always as identity primary key,
  issuer       text not null,
  subject      text not null,
  email        text,
  display_name text,
  unique (issuer, subject)
);

create table app.orgs (
  id   bigint generated always as identity primary key,
  name text not null unique
);

create table app.role_assignments (
  user_id   bigint not null references app.users,
  role_code text   not null references app.roles,
  org_id    bigint not null references app.orgs,
  source    text   not null default 'local' check (source in ('local', 'idp')),
  primary key (user_id, role_code, org_id)
);

-- IdP group -> app role. Group IDs, never display names: a renamed group must not gain rights.
create table app.idp_group_role_mappings (
  issuer    text   not null,
  group_id  text   not null,
  role_code text   not null references app.roles,
  org_id    bigint not null references app.orgs,
  primary key (issuer, group_id, role_code, org_id)
);

create table app.projects (
  id         bigint generated always as identity primary key,
  org_id     bigint not null references app.orgs,
  name       text   not null check (char_length(name) between 1 and 100),
  created_at timestamptz not null default now()
);

-- Server-side sessions (scs/pgxstore). Read before anyone is signed in.
create table app.sessions (
  token  text primary key,
  data   bytea not null,
  expiry timestamptz not null
);
create index sessions_expiry_idx on app.sessions (expiry);

-- Append-only: rows arrive only through the audit trigger.
create table app.audit_log (
  id         bigint generated always as identity primary key,
  at         timestamptz not null default now(),
  actor_id   bigint,  -- null = system (login sync, migration, seed)
  table_name text not null,
  op         text not null,
  row_key    jsonb,
  old        jsonb,
  new        jsonb
);

-- +goose StatementBegin
create function app.current_user_id() returns bigint
language sql stable
as $$ select nullif(current_setting('app.user_id', true), '')::bigint $$;
-- +goose StatementEnd

-- p_org_id null = "in any org" (the coarse check of the API interceptor).
-- +goose StatementBegin
create function app.has_privilege(p_privilege text, p_org_id bigint) returns boolean
language sql stable security definer set search_path = app, pg_temp
as $$
  select exists (
    select 1
      from app.role_assignments ra
      join app.role_privileges rp on rp.role_code = ra.role_code
     where ra.user_id = app.current_user_id()
       and rp.privilege_code = p_privilege
       and (p_org_id is null or ra.org_id = p_org_id))
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function app.upsert_login_user(p_issuer text, p_subject text, p_email text, p_display_name text)
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

-- Replaces only the IdP-sourced assignments; local ones stay. Touches only the diff,
-- so the audit log shows exactly which roles a login added or removed.
-- +goose StatementBegin
create function app.sync_idp_roles(p_user_id bigint, p_issuer text, p_group_ids text[])
returns void
language plpgsql security definer set search_path = app, pg_temp
as $$
begin
  delete from app.role_assignments ra
   where ra.user_id = p_user_id
     and ra.source = 'idp'
     and not exists (
       select 1 from app.idp_group_role_mappings m
        where m.issuer = p_issuer and m.group_id = any (p_group_ids)
          and m.role_code = ra.role_code and m.org_id = ra.org_id);

  insert into app.role_assignments (user_id, role_code, org_id, source)
  select distinct p_user_id, m.role_code, m.org_id, 'idp'
    from app.idp_group_role_mappings m
   where m.issuer = p_issuer and m.group_id = any (p_group_ids)
  on conflict do nothing;
end
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function app.audit() returns trigger
language plpgsql security definer set search_path = app, pg_temp
as $$
declare
  v_row jsonb := to_jsonb(coalesce(new, old));
begin
  insert into app.audit_log (actor_id, table_name, op, row_key, old, new)
  values (app.current_user_id(), tg_table_name, tg_op,
          case when v_row ? 'id' then jsonb_build_object('id', v_row -> 'id') else v_row end,
          case when tg_op <> 'INSERT' then to_jsonb(old) end,
          case when tg_op <> 'DELETE' then to_jsonb(new) end);
  return null;
end
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function app.deny_truncate() returns trigger
language plpgsql
as $$ begin raise exception 'audit_log is append-only'; end $$;
-- +goose StatementEnd

create trigger projects_audit after insert or update or delete on app.projects
  for each row execute function app.audit();
create trigger role_assignments_audit after insert or update or delete on app.role_assignments
  for each row execute function app.audit();
create trigger idp_mappings_audit after insert or update or delete on app.idp_group_role_mappings
  for each row execute function app.audit();
create trigger audit_log_no_truncate before truncate on app.audit_log
  for each statement execute function app.deny_truncate();

-- Row level security on every table, FORCE so the owner is bound too.
alter table app.privileges              enable row level security;
alter table app.privileges              force  row level security;
alter table app.roles                   enable row level security;
alter table app.roles                   force  row level security;
alter table app.role_privileges         enable row level security;
alter table app.role_privileges         force  row level security;
alter table app.users                   enable row level security;
alter table app.users                   force  row level security;
alter table app.orgs                    enable row level security;
alter table app.orgs                    force  row level security;
alter table app.role_assignments        enable row level security;
alter table app.role_assignments        force  row level security;
alter table app.idp_group_role_mappings enable row level security;
alter table app.idp_group_role_mappings force  row level security;
alter table app.projects                enable row level security;
alter table app.projects                force  row level security;
alter table app.sessions                enable row level security;
alter table app.sessions                force  row level security;
alter table app.audit_log               enable row level security;
alter table app.audit_log               force  row level security;

-- The owner (migrations, SECURITY DEFINER functions) may change everything except the audit log.
create policy owner_all on app.privileges              to app_owner using (true) with check (true);
create policy owner_all on app.roles                   to app_owner using (true) with check (true);
create policy owner_all on app.role_privileges         to app_owner using (true) with check (true);
create policy owner_all on app.users                   to app_owner using (true) with check (true);
create policy owner_all on app.orgs                    to app_owner using (true) with check (true);
create policy owner_all on app.role_assignments        to app_owner using (true) with check (true);
create policy owner_all on app.idp_group_role_mappings to app_owner using (true) with check (true);
create policy owner_all on app.projects                to app_owner using (true) with check (true);
create policy owner_all on app.sessions                to app_owner using (true) with check (true);
create policy owner_read   on app.audit_log for select to app_owner using (true);
create policy owner_insert on app.audit_log for insert to app_owner with check (true);

-- Runtime role.
create policy app_rw_read on app.privileges      for select to app_rw using (true);
create policy app_rw_read on app.roles           for select to app_rw using (true);
create policy app_rw_read on app.role_privileges for select to app_rw using (true);
create policy app_rw_own  on app.users            for select to app_rw using (id = app.current_user_id());
create policy app_rw_own  on app.role_assignments for select to app_rw using (user_id = app.current_user_id());
create policy app_rw_read on app.orgs             for select to app_rw using (app.has_privilege('org.read', id));
create policy app_rw_read  on app.projects for select to app_rw using (app.has_privilege('project.read', org_id));
create policy app_rw_write on app.projects for insert to app_rw with check (app.has_privilege('project.write', org_id));
create policy app_rw_update on app.projects for update to app_rw
  using (app.has_privilege('project.write', org_id)) with check (app.has_privilege('project.write', org_id));
create policy app_rw_delete on app.projects for delete to app_rw using (app.has_privilege('project.write', org_id));
-- Sessions are looked up by an unguessable token before anyone is signed in.
create policy app_rw_all on app.sessions to app_rw using (true) with check (true);

grant usage on schema app to app_rw;
grant select on app.privileges, app.roles, app.role_privileges, app.users, app.orgs, app.role_assignments to app_rw;
grant select, insert, update, delete on app.projects, app.sessions to app_rw;
grant execute on function app.current_user_id(), app.has_privilege(text, bigint),
  app.upsert_login_user(text, text, text, text), app.sync_idp_roles(bigint, text, text[]) to app_rw;

-- +goose Down
drop schema app cascade;
