-- Development data only (make seed). Runs as superuser after the migrations.
-- Users sign in at the mock IdP with the subject as username:
--   alice  admin in Acme, viewer in Globex (local roles)
--   bob    viewer in Acme
--   carol  editor in Globex
--   dave   no local role; sign in with claims {"groups": ["acme-editors"]} to become editor in Acme via IdP mapping
\set issuer 'http://127.0.0.1:8091/default'

insert into app.orgs (name) values ('Acme'), ('Globex') on conflict do nothing;

insert into app.users (issuer, subject, email, display_name) values
  (:'issuer', 'alice', 'alice@example.com', 'Alice Admin'),
  (:'issuer', 'bob',   'bob@example.com',   'Bob Viewer'),
  (:'issuer', 'carol', 'carol@example.com', 'Carol Editor')
on conflict do nothing;

insert into app.role_assignments (user_id, role_code, org_id)
select u.id, v.role, o.id
  from (values ('alice', 'admin', 'Acme'), ('alice', 'viewer', 'Globex'),
               ('bob', 'viewer', 'Acme'), ('carol', 'editor', 'Globex')) v (subject, role, org)
  join app.users u on u.issuer = :'issuer' and u.subject = v.subject
  join app.orgs o on o.name = v.org
on conflict do nothing;

insert into app.idp_group_role_mappings (issuer, group_id, role_code, org_id)
select :'issuer', 'acme-editors', 'editor', id from app.orgs where name = 'Acme'
on conflict do nothing;

insert into app.projects (org_id, name)
select o.id, v.name
  from (values ('Acme', 'Website relaunch'), ('Acme', 'Customer portal'), ('Globex', 'Data platform')) v (org, name)
  join app.orgs o on o.name = v.org
 where not exists (select 1 from app.projects p where p.name = v.name);
