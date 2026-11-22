-- Cluster roles for local development and tests (idempotent). Production creates
-- them through its own infrastructure with real secrets; these passwords are dev-only.
do $$
begin
  if not exists (select from pg_roles where rolname = 'app_owner') then
    create role app_owner login password 'app_owner';
  end if;
  if not exists (select from pg_roles where rolname = 'app_rw') then
    create role app_rw login password 'app_rw' nosuperuser nocreatedb nocreaterole nobypassrls;
  end if;
end $$;


-- Resource limits for the runtime role: a runaway query, a lock queue or a transaction left
-- open cannot hold connections and locks for long. Production roles need the same settings
-- (invariants_test.go checks them on every test database).
alter role app_rw set statement_timeout = '5s';
alter role app_rw set lock_timeout = '2s';
alter role app_rw set idle_in_transaction_session_timeout = '10s';
