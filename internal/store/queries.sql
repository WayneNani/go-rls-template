-- No WHERE clauses for authorization here: Postgres RLS filters every row by app.user_id.

-- name: HasPrivilegeAnywhere :one
select app.has_privilege(sqlc.arg(privilege)::text, null::bigint)::boolean as allowed;

-- Email through app.user_emails (app_rw cannot select it); reading your own is not audited.
-- name: CurrentUser :one
select u.id, u.subject, u.display_name,
       coalesce((select e.email from app.user_emails(array[u.id]) e), '')::text as email
  from app.users u
 where u.id = app.current_user_id();

-- RLS also shows managers the assignments of others in their orgs: filter to the caller.
-- name: MyRoles :many
select ra.role_code, ra.source, o.id as org_id, o.name as org_name
  from app.role_assignments ra
  join app.orgs o on o.id = ra.org_id
 where ra.user_id = app.current_user_id()
 order by o.name, ra.role_code;

-- name: MyPrivileges :many
select distinct ra.org_id, rp.privilege_code
  from app.role_assignments ra
  join app.role_privileges rp on rp.role_code = ra.role_code
 where ra.user_id = app.current_user_id()
 order by ra.org_id, rp.privilege_code;

-- Keyset pagination: newest first, continue after (after_created_at, after_id). The filter only
-- removes rows, so the key of the last row returned stays a correct place to continue.
-- name: ListProjects :many
select p.id, p.name, p.created_at, p.version, o.id as org_id, o.name as org_name
  from app.projects p
  join app.orgs o on o.id = p.org_id
 where (sqlc.narg(after_created_at)::timestamptz is null
        or (p.created_at, p.id) < (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::bigint))
   -- Filter: contains, ignoring case; '' matches all. strpos needs no escaping of % and _.
   -- ponytail: scans the visible rows; add a pg_trgm index when lists get large.
   and strpos(lower(p.name), lower(sqlc.arg(query)::text)) > 0
 order by p.created_at desc, p.id desc
 limit sqlc.arg(page_limit)::int;

-- name: CreateProject :one
insert into app.projects (org_id, name)
values (sqlc.arg(org_id), sqlc.arg(name))
returning id;

-- FOR UPDATE applies the RLS update policy too: no row means missing, not visible or not
-- writable for the caller, on purpose indistinguishable.
-- name: LockProject :one
select version from app.projects where id = sqlc.arg(id) for update;

-- The version trigger bumps version.
-- name: RenameProject :one
update app.projects set name = sqlc.arg(name) where id = sqlc.arg(id) returning version;

-- name: UpsertLoginUser :one
select app.upsert_login_user(sqlc.arg(issuer)::text, sqlc.arg(subject)::text,
                             sqlc.narg(email)::text, sqlc.narg(display_name)::text)::bigint as user_id;

-- name: SyncIdpRoles :exec
select app.sync_idp_roles(sqlc.arg(user_id)::bigint, sqlc.arg(issuer)::text, sqlc.arg(group_ids)::text[]);

-- name: RecordAuthEvent :exec
select app.record_auth_event(sqlc.arg(op)::text, sqlc.narg(user_id)::bigint, sqlc.narg(issuer)::text,
                             sqlc.narg(subject)::text, sqlc.narg(detail)::text, sqlc.narg(client_ip)::inet);

-- Role management (AccessService). RLS limits every statement to orgs the caller manages.

-- name: HasPrivilegeIn :one
select app.has_privilege(sqlc.arg(privilege)::text, sqlc.arg(org_id)::bigint)::boolean as allowed;

-- name: ListRoleCatalog :many
select r.code, coalesce(array_agg(rp.privilege_code order by rp.privilege_code)
                        filter (where rp.privilege_code is not null), '{}')::text[] as privileges
  from app.roles r
  left join app.role_privileges rp on rp.role_code = r.code
 group by r.code
 order by r.code;

-- Keyset pagination by user id.
-- name: ListMembers :many
select u.id, u.subject, u.display_name,
       array_agg(ra.role_code order by ra.role_code)::text[] as roles,
       array_agg(ra.source order by ra.role_code)::text[] as sources
  from app.role_assignments ra
  join app.users u on u.id = ra.user_id
 where ra.org_id = sqlc.arg(org_id)
   and (sqlc.narg(after_id)::bigint is null or u.id > sqlc.narg(after_id)::bigint)
   and (strpos(lower(coalesce(u.display_name, '')), lower(sqlc.arg(query)::text)) > 0
        or strpos(lower(u.subject), lower(sqlc.arg(query)::text)) > 0)
 group by u.id
 order by u.id
 limit sqlc.arg(page_limit)::int;

-- Audited: a call that returns someone else's email writes one READ row (app.user_emails).
-- name: UserEmails :many
select e.user_id::bigint as user_id, coalesce(e.email, '')::text as email
  from app.user_emails(sqlc.arg(user_ids)::bigint[]) e;

-- 0 when no user has this email.
-- name: FindUserByEmail :one
select coalesce(app.find_user_by_email(sqlc.arg(email)::text), 0)::bigint as user_id;

-- Zero rows: the user already holds the role (locally or through the IdP).
-- name: GrantRole :execrows
insert into app.role_assignments (user_id, role_code, org_id, source)
values (sqlc.arg(user_id), sqlc.arg(role_code), sqlc.arg(org_id), 'local')
on conflict do nothing;

-- Zero rows: the assignment does not exist or a guard refused it (RLS hides which).
-- name: RevokeRole :execrows
delete from app.role_assignments
 where org_id = sqlc.arg(org_id) and user_id = sqlc.arg(user_id) and role_code = sqlc.arg(role_code)
   and source = 'local';

-- Admin-maintained and small; capped instead of paginated.
-- RLS shows the caller's own IdP only, so (group_id, role_code) is unique here.
-- name: ListGroupMappings :many
select group_id, role_code
  from app.idp_group_role_mappings
 where org_id = sqlc.arg(org_id)
   and (sqlc.narg(after_group_id)::text is null
        or (group_id, role_code) > (sqlc.narg(after_group_id)::text, sqlc.narg(after_role_code)::text))
 order by group_id, role_code
 limit sqlc.arg(page_limit)::int;

-- name: AddGroupMapping :exec
insert into app.idp_group_role_mappings (issuer, group_id, role_code, org_id)
select u.issuer, sqlc.arg(group_id), sqlc.arg(role_code), sqlc.arg(org_id)
  from app.users u
 where u.id = app.current_user_id()
on conflict do nothing;

-- name: RemoveGroupMapping :execrows
delete from app.idp_group_role_mappings
 where org_id = sqlc.arg(org_id) and group_id = sqlc.arg(group_id) and role_code = sqlc.arg(role_code);
