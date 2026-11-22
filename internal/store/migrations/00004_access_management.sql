-- Role management in the app: managers assign roles and IdP group mappings in their org.
-- The guards are RLS policies, so they hold for every caller, not only the API:
--   * only with access.manage in that org
--   * never on your own assignments
--   * only roles whose privileges the caller holds in that org (no escalation)
--   * IdP-sourced assignments are read-only (the IdP decides them at sign-in)
--   * never a mapping for a group the caller is in (a self-grant through the IdP)
--   * a removed mapping removes the IdP roles it backed at once
-- The role catalog (what a role may do) stays in migrations and is not editable here.

-- +goose Up
insert into app.privileges (code) values ('access.manage');
insert into app.role_privileges (role_code, privilege_code) values ('admin', 'access.manage');

-- The caller holds every privilege of p_role in p_org_id.
-- +goose StatementBegin
create function app.can_grant(p_role text, p_org_id bigint) returns boolean
language sql stable
as $$
  select not exists (
    select 1 from app.role_privileges rp
     where rp.role_code = p_role
       and not app.has_privilege(rp.privilege_code, p_org_id))
$$;
-- +goose StatementEnd

-- A manager looks up one user by exact email to grant a first role; there is no user
-- directory. Only users of the caller's own IdP (issuer): the same email at another IdP
-- is another identity. null when unknown (or the caller manages nothing), an error when
-- ambiguous.
-- +goose StatementBegin
create function app.find_user_by_email(p_email text) returns bigint
language plpgsql stable security definer set search_path = app, pg_temp
as $$
declare
  v_ids bigint[];
begin
  if not app.has_privilege('access.manage', null) then
    return null;
  end if;
  select array_agg(u.id) into v_ids
    from app.users u
   where lower(u.email) = lower(p_email)
     and u.issuer = (select c.issuer from app.users c where c.id = app.current_user_id());
  if cardinality(v_ids) > 1 then
    raise exception 'more than one user with this email' using errcode = 'P0003';
  end if;
  return v_ids[1];
end
$$;
-- +goose StatementEnd

grant execute on function app.can_grant(text, bigint), app.find_user_by_email(text) to app_rw;

-- The IdP groups of each user, recorded at sign-in. They decide which IdP-sourced roles
-- a user still holds when a mapping goes away, and keep managers from mapping a group
-- they belong to themselves.
alter table app.users add column idp_groups text[] not null default '{}';

-- +goose StatementBegin
create or replace function app.sync_idp_roles(p_user_id bigint, p_issuer text, p_group_ids text[])
returns void
language plpgsql security definer set search_path = app, pg_temp
as $$
begin
  update app.users set idp_groups = coalesce(p_group_ids, '{}')
   where id = p_user_id and idp_groups is distinct from coalesce(p_group_ids, '{}');

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

-- A removed mapping takes its roles away at once, not only at the members' next sign-in:
-- IdP-sourced assignments that no remaining mapping backs are deleted.
-- +goose StatementBegin
create function app.drop_unbacked_idp_roles() returns trigger
language plpgsql security definer set search_path = app, pg_temp
as $$
begin
  delete from app.role_assignments ra
   where ra.source = 'idp' and ra.org_id = old.org_id and ra.role_code = old.role_code
     and not exists (
       select 1 from app.idp_group_role_mappings m
         join app.users u on u.id = ra.user_id
        where m.org_id = ra.org_id and m.role_code = ra.role_code
          and m.issuer = u.issuer and m.group_id = any (u.idp_groups));
  return null;
end
$$;
-- +goose StatementEnd

create trigger idp_mappings_cleanup after delete on app.idp_group_role_mappings
  for each row execute function app.drop_unbacked_idp_roles();

-- Users and their recorded email and groups are audited too (only real changes; the
-- upsert at every sign-in rewrites unchanged rows).
create trigger users_audit after insert or delete on app.users
  for each row execute function app.audit();
create trigger users_audit_update after update on app.users
  for each row when (old.* is distinct from new.*) execute function app.audit();

-- The target user belongs to the caller's IdP. Only says yes or no, so it reveals no more
-- than the foreign key already does.
-- +goose StatementBegin
create function app.shares_my_issuer(p_user_id bigint) returns boolean
language sql stable security definer set search_path = app, pg_temp
as $$
  select exists (select 1 from app.users t, app.users me
                  where t.id = p_user_id and me.id = app.current_user_id() and t.issuer = me.issuer)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
create function app.my_issuer() returns text
language sql stable
as $$ select u.issuer from app.users u where u.id = app.current_user_id() $$;
-- +goose StatementEnd

grant execute on function app.shares_my_issuer(bigint), app.my_issuer() to app_rw;

-- Managers see the assignments in their orgs and the users who hold them.
drop policy app_rw_own on app.role_assignments;
create policy app_rw_read on app.role_assignments for select to app_rw
  using (user_id = app.current_user_id() or app.has_privilege('access.manage', org_id));

drop policy app_rw_own on app.users;
create policy app_rw_read on app.users for select to app_rw
  using (id = app.current_user_id()
         or exists (select 1 from app.role_assignments ra where ra.user_id = users.id));

grant insert, delete on app.role_assignments to app_rw;
create policy app_rw_grant on app.role_assignments for insert to app_rw
  with check (source = 'local' and user_id <> app.current_user_id() and app.shares_my_issuer(user_id)
              and app.has_privilege('access.manage', org_id) and app.can_grant(role_code, org_id));
create policy app_rw_revoke on app.role_assignments for delete to app_rw
  using (source = 'local' and user_id <> app.current_user_id()
         and app.has_privilege('access.manage', org_id) and app.can_grant(role_code, org_id));

-- Mappings of the caller's own IdP only, and never for a group the caller is in
-- (that would be a self-grant through the IdP).
grant select, insert, delete on app.idp_group_role_mappings to app_rw;
create policy app_rw_read on app.idp_group_role_mappings for select to app_rw
  using (app.has_privilege('access.manage', org_id) and issuer = app.my_issuer());
create policy app_rw_add on app.idp_group_role_mappings for insert to app_rw
  with check (app.has_privilege('access.manage', org_id) and app.can_grant(role_code, org_id)
              and issuer = app.my_issuer()
              and not exists (select 1 from app.users u
                               where u.id = app.current_user_id() and group_id = any (u.idp_groups)));
create policy app_rw_remove on app.idp_group_role_mappings for delete to app_rw
  using (app.has_privilege('access.manage', org_id) and app.can_grant(role_code, org_id)
         and issuer = app.my_issuer());

-- +goose Down
drop policy app_rw_remove on app.idp_group_role_mappings;
drop policy app_rw_add on app.idp_group_role_mappings;
drop policy app_rw_read on app.idp_group_role_mappings;
revoke select, insert, delete on app.idp_group_role_mappings from app_rw;
drop policy app_rw_revoke on app.role_assignments;
drop policy app_rw_grant on app.role_assignments;
revoke insert, delete on app.role_assignments from app_rw;
drop policy app_rw_read on app.users;
create policy app_rw_own on app.users for select to app_rw using (id = app.current_user_id());
drop function app.my_issuer();
drop function app.shares_my_issuer(bigint);
drop trigger users_audit_update on app.users;
drop trigger users_audit on app.users;
drop trigger idp_mappings_cleanup on app.idp_group_role_mappings;
drop function app.drop_unbacked_idp_roles();
-- +goose StatementBegin
create or replace function app.sync_idp_roles(p_user_id bigint, p_issuer text, p_group_ids text[])
returns void
language plpgsql security definer set search_path = app, pg_temp
as $$
begin
  delete from app.role_assignments ra
   where ra.user_id = p_user_id and ra.source = 'idp'
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
alter table app.users drop column idp_groups;
drop policy app_rw_read on app.role_assignments;
create policy app_rw_own on app.role_assignments for select to app_rw using (user_id = app.current_user_id());
drop function app.find_user_by_email(text);
drop function app.can_grant(text, bigint);
delete from app.role_privileges where privilege_code = 'access.manage';
delete from app.privileges where code = 'access.manage';
