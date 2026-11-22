-- Sign-ins, failed sign-ins and sign-outs go into the audit log; org changes are audited too.

-- +goose Up
create trigger orgs_audit after insert or update or delete on app.orgs
  for each row execute function app.audit();

-- op: LOGIN, LOGIN_FAILED or LOGOUT. p_user_id is null when the user is not known yet.
-- +goose StatementBegin
create function app.record_auth_event(p_op text, p_user_id bigint, p_issuer text, p_subject text, p_detail text)
returns void
language sql security definer set search_path = app, pg_temp
as $$
  insert into app.audit_log (actor_id, table_name, op, row_key, new)
  select p_user_id, 'auth', p_op, null,
         jsonb_strip_nulls(jsonb_build_object('issuer', p_issuer, 'subject', p_subject, 'detail', left(p_detail, 200)))
   where p_op in ('LOGIN', 'LOGIN_FAILED', 'LOGOUT')
$$;
-- +goose StatementEnd

grant execute on function app.record_auth_event(text, bigint, text, text, text) to app_rw;

-- +goose Down
revoke execute on function app.record_auth_event(text, bigint, text, text, text) from app_rw;
drop function app.record_auth_event(text, bigint, text, text, text);
drop trigger orgs_audit on app.orgs;
