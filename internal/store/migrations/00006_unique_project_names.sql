-- Project names are unique per org. A duplicate arrives at the name field of CreateProject and
-- UpdateProject (constraintFields in internal/api/constraints.go), not as a generic error.

-- Outside a transaction: the index is built concurrently, so writers are not blocked while it
-- builds; only attaching it as the constraint takes a short exclusive lock. goose runs this file
-- on one connection, closed afterwards, so the session settings end with it.
-- +goose NO TRANSACTION
-- +goose Up
set lock_timeout = '5s';
set statement_timeout = '10min';
create unique index concurrently if not exists projects_org_id_name_key on app.projects (org_id, name);

begin;
alter table app.projects add constraint projects_org_id_name_key unique using index projects_org_id_name_key;
commit;

-- +goose Down
alter table app.projects drop constraint if exists projects_org_id_name_key;
