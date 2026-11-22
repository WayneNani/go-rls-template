# go-rls-template

A starting point for business apps where security and auditability are enforced by tests,
linters and the database, not by memory.

- **Contract first**: every RPC in `proto/` declares the privilege it needs. A method without one is denied.
- **Database decides**: Postgres row-level security on every table, identity set per transaction.
  The app role owns nothing and cannot read or change the audit log.
- **Any OIDC IdP**, roles from IdP groups via a mapping table, server-side sessions.
- **Small, pinned supply chain**: Go tools in `go.mod`, pnpm with a 7-day release cooldown and no
  install scripts, images and actions pinned by digest/SHA, Renovate keeps them current.

## Quick start

Needs Go, Node and Docker.

```bash
make init MODULE=github.com/acme/portal NAME="Acme Portal"   # once: make it your project
make setup   # Postgres + mock IdP, git hooks, dependencies, migrations, demo data, frontend build
make run     # http://localhost:8090
```

Sign in at the mock IdP with any of these usernames:

| User | Access |
|---|---|
| `alice` | admin in Acme, viewer in Globex |
| `bob` | viewer in Acme |
| `carol` | editor in Globex |
| `dave` + claims `{"groups": ["acme-editors"]}` | editor in Acme through the IdP group mapping |

| Command | What it does |
|---|---|
| `make dev` | Hot reload: Vite on http://localhost:5173 in front of the Go server |
| `make scaffold NAME=invoice FIELDS="title:text amount:int due:date paid:bool"` | New org-scoped entity in every layer (below) |
| `make check` | Code generation up to date, all linters, all Go tests (needs `make up`) |
| `make e2e` | Browser tests (desktop and mobile): sign-in, roles, dialogs, step-up, no CSP violation, axe on every screen |
| `make vuln` | Known vulnerabilities in Go code paths and shipped frontend packages |
| `make secrets` | Secrets anywhere in the git history |

New feature? In Claude Code the `add-feature` skill walks the chain from migration to UI.

**New entity: `make scaffold`** (`cmd/scaffold`, Go `text/template`, no runtime framework). It writes
an org-scoped entity in the shape of projects, as plain code you then own and edit:

- migration: table with RLS + `FORCE`, policies per privilege, column-level update grant, `version`
  trigger, audit trigger, privileges `<name>.read` (viewer, editor, admin) and `<name>.write` (editor, admin)
- queries (keyset paging, `query` filter on the label, version-checked update), proto service with
  privileges and protovalidate rules, handler, constraint mappings, a handler test (lost update,
  taken label, invalid date), access-matrix rows and their calls
- a page with `<DataTable>` and create/edit dialogs in the navigation, an E2E spec with axe

Field types: `text` (1-200 characters, trimmed), `int` (bigint, at least 0), `date`, `bool`; the first
field is the label (text, unique per org, filtered). `PLURAL=` overrides the plural. Names are checked
strictly (snake_case letters, no SQL/Go/TS keywords or existing names). It refuses, writing nothing,
if any part of the entity exists. Then `make generate check migrate e2e`. No delete RPC is generated.
`TestScaffoldedEntitiesPassTheChecks` (part of `make test`, so CI and the Stop hook) scaffolds two
entities into a copy of the repo and runs generate, linters and the Go tests there.

## How the rules are enforced

| Rule | Where it is enforced |
|---|---|
| Every RPC of every service declares a privilege; public ones are allowlisted; services are mounted only with the interceptor | `internal/api/contract_test.go`, interceptor denies otherwise, `forbidigo` on `*connect.New*Handler` |
| Each role can do exactly what the access matrix says, per org; every RPC has a row | [`docs/access-matrix.md`](docs/access-matrix.md), read and run by `internal/api/matrix_test.go` (real interceptor, store and RLS) |
| Role management in the app: managers grant roles and map IdP groups in their own org and IdP, never for themselves (not even through a group they are in), never beyond their own privileges; IdP roles read-only; a removed mapping removes the roles it backed at once | RLS policies and triggers of migration 00004, `access_guards_test.go`, `frontend/e2e/access.spec.ts` |
| Nothing outside schema `app`; RLS on every table, `FORCE`; invoker views; definer allowlist without overloads; unprivileged app role; audit log append-only (even for superusers, via triggers); every table audited or deliberately exempt | `internal/store/invariants_test.go` |
| Access changes need a recent sign-in (step-up): RPCs declare `option (authz.v1.max_auth_age)`, the interceptor answers "recent sign-in required" when the IdP's `auth_time` is older, the UI re-authenticates with `max_age=0`/`prompt=login` and returns to a strictly checked same-origin path | `internal/authz` (`authz_test.go`), `TestAccessChangesNeedRecentSignIn` in `contract_test.go`, `safeReturn` in `internal/auth` (`login_test.go`), `frontend/e2e/access.spec.ts`; `authz.WithUser` (fresh sign-in) is test-only via `forbidigo` |
| Optional: every sign-in must carry a given `acr` (e.g. MFA) | `OIDC_REQUIRED_ACR`, sent as `acr_values` and checked in `internal/auth` |
| No axe violations on any screen, dialog or select, desktop and mobile; a disabled rule needs a reason | `frontend/e2e/axe.ts`, `frontend/e2e/a11y.spec.ts` |
| Sign-ins, failed sign-ins and sign-outs are audited with client IP and a fixed reason code | `app.record_auth_event`, `auth_events_test.go` |
| Session tokens are stored hashed | `HashTokenInStore` in `internal/auth/sessions.go`, `sessions_test.go` |
| Lists are paginated (keyset); malformed page tokens are rejected, and a forged one only moves the start (RLS still filters) | `internal/api/paging.go`, `paging_test.go`; every `List*` RPC has a bounded `page_size`, `page_token` and `next_page_token` unless allowlisted with a reason (`TestListsArePaginated`); the optional `query` filter keeps keyset paging correct (`paging_test.go`); screens use `<DataTable>` (`src/components/data-table.tsx`) |
| Input rules are declared once in proto (protovalidate) on every request field, enforced by the server for every RPC and shown at the field in the UI; the database constraints stay as the last line | `TestEveryRequestFieldHasRules` (rule or explicit ignore; rules compile), interceptor in `api.NewHandler`, `src/lib/field-errors.ts`, `frontend/e2e/smoke.spec.ts` |
| A violated database constraint (e.g. a taken project name) arrives at its request field in the same format as a proto rule, without database messages or constraint names; every constraint the app role can violate is mapped or listed as not user-facing with a reason | `constraintFields` in `internal/api/constraints.go`, `TestEveryConstraintIsMapped` (also fails for a mapping to a constraint or field that no longer exists), `matrix_test.go`, `frontend/e2e/smoke.spec.ts` |
| Validation runs after authorization: callers without access get Unauthenticated/PermissionDenied, never the rules | interceptor order in `api.NewHandler`, `TestValidationAfterAuthorization` |
| DB access only through `internal/store`; claims only in `internal/auth` | `depguard` in `.golangci.yml` |
| Routes only in `cmd/server`, services only via `api.NewHandler`, no `template.HTML` | `forbidigo` in `.golangci.yml` |
| No raw HTML, `fetch` or browser storage in the frontend | `frontend/eslint.config.js` |
| Trusted Types enforced: raw HTML reaches the DOM only if it is on the exact allowlist; violations are reported and fail `make e2e` | `frontend/src/trusted-types.ts`, CSP in `internal/web/web.go` (`web_test.go`), `frontend/e2e/smoke.spec.ts` |
| No `unsafe-inline` anywhere: injected `<style>` tags need the per-response nonce in `index.html` | `internal/web/web.go` (`index_test.go`), `frontend/src/csp-nonce.ts`, `make e2e` |
| Logs and traces never carry emails, tokens, cookies, query strings or SQL arguments: logs get request id, trace id and the internal user id; email-like text and secret-named keys are redacted; database spans keep the SQL text, never arguments or values from error messages | `internal/telemetry` (`telemetry_test.go`), `internal/store/trace.go` (`trace_test.go`); `depguard`/`forbidigo` keep SDK, exporters and `otelpgx` setup in those two places |
| CSP, HSTS, nosniff, no framing, CSRF | `internal/web/web.go`, `http.CrossOriginProtection` in `cmd/server` (denials are logged) |
| Session cookie `SameSite=Strict`; only the 10-minute login transaction is `Lax` | `internal/auth/sessions.go`, `sessions_test.go`; the dev IdP runs on another site (127.0.0.1) so the cross-site login is exercised locally |
| Rate limits per client IP on API, sign-in and CSP reports | `internal/ratelimit`, `routes()` in `cmd/server` |
| Database connections (server and `cmd/migrate`) verify TLS (`sslmode=verify-full`) unless `INSECURE_DEV=true` | `internal/store/store.go`, `tls_test.go`, `make lint-rules` keeps the flag out of Dockerfile, compose and CI |
| Applied migrations never change (fixes are new migrations) | `make migrations-immutable` in CI against the PR base |
| No `nolint` for depguard, forbidigo or gosec; no inline `eslint-disable` in app code | `make lint-rules`, `nolintlint`, `noInlineConfig` in `eslint.config.js` |
| Generated code matches proto and SQL | CI: `make generate && git diff --exit-code` |
| No secrets in commits | `.githooks/pre-commit` (staged changes), `make secrets` in CI (whole history) |
| Known vulnerabilities | `govulncheck` (reachable code only), `pnpm audit --prod` on every PR and nightly (`scan.yml`), dependency review on PRs |
| Workflow security | `actionlint` (`make lint`), `zizmor` in CI, actions pinned by SHA, `permissions: read` |
| Releases are traceable | `release.yml`: all CI gates, tagged commit must be on the default branch, then image with SBOM, cosign signature and build provenance; the image is also built on every PR |
| Only admins create release tags | tag ruleset in `scripts/github-ruleset.sh` |
| Security-relevant files need security review | `.github/CODEOWNERS` + `scripts/github-ruleset.sh` |

Every audit-relevant write lands in `app.audit_log` with the acting user (`null` = system,
e.g. role sync at login).

## Guards from Oracle APEX (migration 00005)

| Guard | Where it is enforced |
|---|---|
| No lost updates: tables `app_rw` may update carry a `version` the database bumps; `UpdateProject` answers `Aborted` for a stale one, `PermissionDenied` for a row the caller cannot see or change | `app.bump_version()`, `invariants_test.go`, `matrix_test.go` ("stale version") |
| A disabled user is nobody on the very next request (`app.current_user_id()` is null) and cannot sign in | migration 00005, `internal/store/guards_test.go`, `matrix_test.go` |
| Sensitive columns (comment `sensitive:`, e.g. `users.email`) are not selectable by `app_rw`; `app.user_emails` reads them and audits every read of someone else's (`op = 'READ'`, the ids). Reading your own email (WhoAmI) is not logged | `invariants_test.go`, `guards_test.go` |
| `app_rw` runs with `statement_timeout` 5 s, `lock_timeout` 2 s, `idle_in_transaction_session_timeout` 10 s | `dev/roles.sql`, `invariants_test.go` |
| New migrations take no dangerous locks without timeouts (squawk on the Up part; 00001-00004 predate it) | `make lint-migrations` (in `make lint`), `squawk-cli` pinned with lockfile integrity |

**Disabling a user** is an operations task, not an API: users are global across orgs, so no org
admin may lock someone out everywhere. As the owner role (SCIM can set it later):

```sql
update app.users set disabled_at = now() where issuer = '<issuer>' and subject = '<subject>';
update app.users set disabled_at = null  where issuer = '<issuer>' and subject = '<subject>';  -- re-enable
```

The change is audited (`users` row update with actor `null`). The user's open session stays, but
every request is denied from the next one on, and a new sign-in is refused.

**Production roles** need the same settings as `dev/roles.sql` (`alter role app_rw set
statement_timeout = '5s'` and so on); the invariant test checks the dev and test databases only.
The connection pool takes `pool_max_conns` from `DATABASE_URL` (e.g. `...&pool_max_conns=20`);
without it the server uses 10. Keep instances × pool size below the database's `max_connections`.

## Debugging a request

Every response carries `X-Request-Id`; the generic "Something went wrong" message in the UI shows
it as "Reference". Every log line of that request (JSON on stdout) has `request_id`, `trace_id`
and, once the session is known, `user_id` (internal id). Per request there is one `request` line
with method, route pattern, status, duration and, for RPCs, procedure and Connect code. Denials,
step-up failures and validation failures log at info as `rpc rejected` with the procedure;
internal errors as `request failed` with the cause.

```bash
make run | grep '"request_id":"<reference from the UI>"'
```

**Traces** (off by default): set the standard `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP over HTTP; the
SDK reads the other `OTEL_*` variables, e.g. `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER`).
Locally:

```bash
make up-otel   # also starts Jaeger, UI on http://127.0.0.1:16686
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:54318 OTEL_SERVICE_NAME=starter make run
```

In Jaeger pick the service `starter`, then search by trace id or by the tag
`app.request_id=<reference>`. A request shows the HTTP span (route pattern, status), the RPC
span (procedure, code) and one span per SQL statement (SQL text only). An incoming W3C
`traceparent` becomes the parent, so a caller's trace continues here; it is used for
correlation only. Without an endpoint nothing is recorded or exported. Shutdown flushes pending spans.

## Not enforced (needs people)

- Whether a privilege is the *right* one for a method: review the role matrix with the business side.
- Logic bugs inside an allowed operation.
- IdP configuration (MFA, session length), production secrets, TLS termination.
- A pentest before go-live.

## Known trade-offs

- A new UI library that injects `<style>` tags must accept the nonce (`src/csp-nonce.ts`);
  `make e2e` reports it otherwise.
- Users appear in role management after their first sign-in (lookup by exact email within the
  caller's IdP). Only emails the IdP marks `email_verified` are stored, so nobody can claim a
  colleague's address first. For an IdP that omits the claim but only issues addresses it controls
  (some corporate directories), set `OIDC_TRUST_EMAIL=true`. To give access before a first sign-in,
  map an IdP group.
- The database trusts the app for identity (`set_config('app.user_id')`). If the app is compromised
  it can act as any user; RLS still limits each request to one user's rights, and the audit log
  names that user. Verifying the IdP's signed token in the database would close this, but is left
  out on purpose:
  - `pg_session_jwt` checks Ed25519 only (most IdPs sign RS256/ES256), and the client sets the key
    it checks against, so a compromised app could set its own.
  - Checking RS256/ES256 in PL/pgSQL means hand-written crypto; `plpython3u` needs a superuser and
    is missing on most managed Postgres services.
  - The database would also need the IdP's keys kept current and the token refreshed per request.

  Revisit when your IdP and database offer a supported way (an extension on your managed service
  that checks your IdP's algorithm with a key set by the database owner, not the session).

  Looking up the session in the database (as Oracle APEX does) does not help on its own: the app
  creates the session after the OIDC callback, so a compromised app creates one for any user.
  It pays off only with a separate login service whose database role alone may create sessions,
  while the API's role may only resolve a session token to a user. Then a compromised API process
  reaches only the sessions of users signed in at the time. Cost: own session code instead of `scs`
  (token, rotation at login, timeouts, cleanup) and a second process with its own credentials;
  per-request cost stays about the same. Worth it when code execution in the API process is a
  threat you must plan for; the common case, an authorization bug, is already covered by RLS.
- Step-up uses the ID token's `auth_time`. An IdP that omits it is trusted to have honoured
  `max_age=0`/`prompt=login`; the sign-in time is used instead. After step-up the user repeats the
  action; nothing is replayed.
- List filters (`query` on `ListProjects`, `ListMembers`) match names, not emails (`app_rw` cannot
  read them), and scan the visible rows; add a `pg_trgm` index when lists grow. Lists keep the
  server's keyset order: sorting by a column would need a page token per sort key.
- Logout ends the app session only, not the IdP session (add RP-initiated logout if needed).
- IdP roles are synced at sign-in. A removed group or a deprovisioned user keeps access until the
  session ends (8 h, 1 h idle). Shorten the lifetimes or add SCIM if that is too long.
- Rate limits are per client IP as seen by the server. Behind a reverse proxy, read the client IP
  from the proxy's header in `internal/ratelimit` first, or every user shares one bucket.

## Before the first push

1. `make init` (if not done) and replace `@your-org/...` in `.github/CODEOWNERS`.
2. Push, then `scripts/github-ruleset.sh OWNER/REPO`: PRs only, Code Owner review, all CI checks
   required, no bypass; release tags only by admins. `dependency-review` needs GitHub Advanced
   Security on private repositories (see the script).
3. Enable Renovate, Dependabot alerts and secret scanning with push protection.
4. Production: create `app_owner` / `app_rw` with real secrets, run `cmd/migrate` as `app_owner`
   before each deploy, run the server as `app_rw` with `sslmode=verify-full`. Never set `INSECURE_DEV`.

### Not on GitHub?

`.github/CODEOWNERS`, `scripts/github-ruleset.sh` and the workflows are GitHub-specific. The
principle carries over: security-relevant paths need approval from a fixed team, and the
platform must *block* the merge without it. A file that only suggests reviewers protects nothing,
because the checks themselves (tests, linter configs, CI) live in those paths.

| Platform | Code owners | Blocks the merge? |
|---|---|---|
| GitHub | `CODEOWNERS` | Yes, with "Require review from Code Owners" in the branch ruleset |
| GitLab | `CODEOWNERS` (same format, plus sections and approval counts) | Yes, "Code owner approval" on protected branches (Premium tier, unverified) |
| Bitbucket Cloud | `.bitbucket/CODEOWNERS` | Natively mainly suggests reviewers; sources disagree whether it blocks without Premium. Reliable enforcement: Marketplace apps (Code Owners for Bitbucket, Workzone) |
| Azure DevOps | No file: branch policy "Automatically included reviewers" with path filters | Yes, when the policy is set to Required |
| Gerrit | `OWNERS` files (code-owners plugin) | Yes, as a submit requirement |
| Gitea / Forgejo | `CODEOWNERS` | Requests reviews; enforcement not verified |
| OCI DevOps code repositories | Not found | Not verified |

Check the platform's current documentation before relying on a row marked unverified.

## License

MIT, see [LICENSE](LICENSE).
