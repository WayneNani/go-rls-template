-- Audit log: rows can be added, never changed or removed (also not by the owner).
-- Auth events carry the client IP, and their detail is a fixed code, not caller text.

-- +goose Up
-- +goose StatementBegin
create or replace function app.deny_truncate() returns trigger
language plpgsql
as $$ begin raise exception 'audit_log is append-only'; end $$;
-- +goose StatementEnd

create trigger audit_log_append_only before update or delete on app.audit_log
  for each row execute function app.deny_truncate();

drop function app.record_auth_event(text, bigint, text, text, text);

-- p_detail must be one of the codes below; anything else is stored as 'other'.
-- +goose StatementBegin
create function app.record_auth_event(p_op text, p_user_id bigint, p_issuer text, p_subject text,
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

grant execute on function app.record_auth_event(text, bigint, text, text, text, inet) to app_rw;

-- +goose Down
drop function app.record_auth_event(text, bigint, text, text, text, inet);
drop trigger audit_log_append_only on app.audit_log;
-- (the 00002 version of record_auth_event is not restored; migrate down past 00002 instead)
