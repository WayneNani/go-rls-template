# CLAUDE.md

Starter for business apps that are secure and auditable by construction. The rules below are
enforced by tests and linters; `make check` runs them (the Stop hook in `.claude/settings.json`
runs it whenever the working tree has changes). Never weaken a check to make it pass.

## Stack

Go (Connect/protobuf, sqlc + pgx) · Postgres with RLS · React SPA (Vite, shadcn/ui, Tailwind,
TanStack Query) embedded in the Go binary · any OIDC IdP (mock IdP in `compose.yaml` for dev).

## Rules

New business object, table, RPC or screen: use the `add-feature` skill (`.claude/skills/`). A new
org-scoped entity starts with `make scaffold NAME=invoice FIELDS="title:text amount:int due:date paid:bool"`
(`cmd/scaffold`): every layer in the shape of projects, as plain code to edit afterwards. Shared files
carry `scaffold: ... above this line` markers; keep them. `TestScaffoldedEntitiesPassTheChecks`
scaffolds into a copy and runs the checks there, so a template change must keep them passing.

- **Every RPC declares `option (authz.v1.privilege)`** in `proto/`: a code from `app.privileges`,
  `"authenticated"` or `"public"` (public needs an entry in `internal/api/contract_test.go`).
  A new privilege goes into a migration and into the access matrix `docs/access-matrix.md`
  (the specification `matrix_test.go` runs). Roles are assigned in the app (AccessService);
  what a role may do stays in migrations.
- **Access-changing RPCs declare `option (authz.v1.max_auth_age)`** (seconds, at most 900): the
  interceptor then demands a recent IdP sign-in (step-up) and the frontend offers a
  re-authentication. `TestAccessChangesNeedRecentSignIn` requires it on every method that needs
  `access.manage` except the read-only ones listed there. `authz.WithUser` is for tests only.
- **Every table** gets `enable` + `force row level security`, an `owner_all` policy for
  `app_owner` and explicit policies and grants for `app_rw`. Authorization lives in the policies,
  not in `WHERE` clauses. Views use `security_invoker = true`. `SECURITY DEFINER` only with
  `set search_path` and an entry in the allowlist in `internal/store/invariants_test.go`.
  Every table gets the `app.audit()` trigger or a reasoned entry in the exempt list there.
- **Every table `app_rw` may update has `version bigint`**, bumped by a `before update` trigger
  (`app.bump_version()`). Update RPCs take the version the caller read, lock the row
  (`select ... for update`, which applies the RLS update policy), answer `Aborted` when it differs
  (`UpdateProject`). Exempt list in `invariants_test.go`.
- **Sensitive columns** (comment `sensitive: ...`, e.g. `users.email`) are never selectable by
  `app_rw`: grant `app_rw` column lists on such tables and read them only through an audited
  `SECURITY DEFINER` function like `app.user_emails` (one `READ` row per call). Enforced in
  `invariants_test.go`.
- **Input rules live in proto**: every request field gets a `(buf.validate.field)` rule
  (protovalidate), or `ignore: IGNORE_ALWAYS` on purpose; mirror the database constraints, which
  stay. `NewHandler` validates after authz, so a caller without access never sees the rules.
  The UI shows violations at the field (`fieldErrors` in `src/lib/field-errors.ts`) and does not
  repeat the rules (no `maxLength`). `TestEveryRequestFieldHasRules`, `TestValidationAfterAuthorization`.
- **Database constraints answer at the field**: a constraint `app_rw` can violate is mapped to a
  request field and message in `constraintFields` (`internal/api/constraints.go`), sent like a
  protovalidate violation, or listed in `constraintsNotUserFacing` with a reason
  (`TestEveryConstraintIsMapped`). Never put database messages or constraint names in a response.
- **Lists are paginated** (keyset, like `ListProjects`); never return an unbounded list. Every
  `List*` RPC takes `page_size` (with `int32.lte`) and `page_token` and returns `next_page_token`
  (`TestListsArePaginated`); exceptions only in `unpagedLists` with a reason (`ListRoles`).
  Screens render them with `usePagedList` + `<DataTable>` (optional `query` filter, server order).
- **Database access only through `internal/store`** (`WithUser`, `AsLogin`). Queries go into
  `internal/store/queries.sql`, then `make generate`. Never edit `gen/`, `internal/store/db/`,
  `frontend/src/gen/` or `frontend/src/components/ui/` generated parts by hand.
- **Migrations**: new numbered file in `internal/store/migrations/`, never edit an applied one.
- **Routes** only in `cmd/server` `routes()`; Connect services only via `api.NewHandler`.
- **Frontend**: backend calls only through `src/lib/api.ts`; no `fetch`, no raw HTML, no browser
  storage (ESLint). Permission checks in the UI are hints; the server decides.
- **Accessibility**: `make e2e` runs axe (`frontend/e2e/axe.ts`) on every screen and open
  overlay, desktop and mobile. Fix the component; a disabled rule needs a written reason there.
- **Trusted Types are enforced.** A dependency that needs raw HTML gets its exact string added to
  the allowlist in `frontend/src/trusted-types.ts` (security review), never a pass-through policy.
- **Dependencies**: adding one needs a reason in the PR. pnpm waits 7 days for new releases and
  blocks install scripts; keep it that way. Go tools are pinned in `go.mod` and `tools/*/go.mod`.
- Errors to clients are generic (`toConnect`); details go to the log.
- **Logs and traces**: log with the request context (`slog.InfoContext(ctx, ...)`) so the line
  gets request id, trace id and user id. Never log or put on a span emails, tokens, cookies,
  request bodies or query arguments; `internal/telemetry` redacts what it recognises, it is not a
  licence. Tracing setup only in `internal/telemetry`, database spans only via `internal/store`
  (`depguard`, `forbidigo`; `telemetry_test.go`, `trace_test.go`).
- `INSECURE_DEV=true` exists for local development only (plain cookies, unencrypted DB).
  Never set it in a deployment, a Dockerfile or CI config other than the e2e job via `make`.

## Commands

`make up` (`make up-otel` adds Jaeger, README "Debugging a request") · `make setup` (first time) · `make run` (http://localhost:8090) · `make dev` (hot reload, :5173)
· `make scaffold` · `make check` · `make e2e` (after UI changes) · `make vuln` · `make secrets`
