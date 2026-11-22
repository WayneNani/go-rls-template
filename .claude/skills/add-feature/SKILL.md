---
name: add-feature
description: Use when adding a new business object, table, RPC or screen to this app (e.g. "add invoices", "users should be able to archive projects", "new endpoint for X"). Walks the whole chain from migration to UI so RLS, privileges, audit, role matrix and tests stay consistent.
---

# Add a feature end to end

The checks in `make check` and `make e2e` catch most omissions, but only after the fact.
Follow this order; each step names the check that fails if it is skipped.

## 1. Decide access first

Write down, before any code: which roles may read and which may change it, and in which
scope (org). Reuse privileges from `app.privileges` when the meaning is the same; add a new
one (e.g. `invoice.read`, `invoice.write`) only for a new kind of access. Ask the user when
this is not clear from the request. It is the one decision no test can make.

## 1b. A new entity: `make scaffold` first, then edit

For a new org-scoped business object (a table with list, create and edit), generate it instead of
writing steps 2-7 by hand:

```bash
make scaffold NAME=invoice FIELDS="title:text amount:int due:date paid:bool"   # PLURAL=... if not +s/es/ies
make generate check
```

Types: `text`, `int`, `date`, `bool`; the first field is the label (text, unique per org, filtered).
It writes the migration, queries, proto service, handler and its test, constraint mappings, matrix
rows and calls, a page with create/edit dialogs in the navigation, and an E2E spec, and it refuses
without writing anything when the entity exists. The result already passes `make check`.

Then edit the generated code to the real requirement, following the steps below for each change:
privileges and role grants from step 1 (the migration grants `<name>.read` to viewer, editor,
admin and `<name>.write` to editor, admin), field lengths and ranges (change the `check`, the proto
rule and the message in `constraints.go` together), optional fields, a delete RPC, more columns in
the page. Edit the migration only while it is not applied anywhere; afterwards add a new one. Show
the user the new rows in `docs/access-matrix.md`. Run `make migrate e2e` at the end.

Keep the `scaffold: ... above this line` markers in shared files. Changing a template in
`cmd/scaffold/templates` is fine; `TestScaffoldedEntitiesPassTheChecks` must still pass.

Not an entity (a new RPC on an existing one, a field, a screen): follow the steps below by hand.

## 2. Migration (`internal/store/migrations/0000N_<name>.sql`, never edit an applied one)

Always schema-qualify (`app.invoices`): an unqualified `create` lands in `public`.

- Table with `bigint generated always as identity` id; constraints for validation
  (`check`, `not null`, foreign keys) instead of Go code.
- `enable` and `force row level security`; `owner_all` policy for `app_owner`.
- Policies for `app_rw` that call `app.has_privilege('<privilege>', <org column>)`:
  `select` with `using`, `insert` with `with check`, `update` with both, `delete` with `using`.
- `grant` only the statements the app needs to `app_rw`.
- `create trigger <table>_audit after insert or update or delete ... execute function app.audit()`,
  or add the table to the exempt list in `invariants_test.go` with a reason.
- If `app_rw` may `update` it: `version bigint not null default 1` and
  `create trigger <table>_version before update ... execute function app.bump_version()`.
  The update RPC takes the expected version, locks the row (`select version ... for update`),
  returns `Aborted` on a mismatch and the new version on success (see `UpdateProject`).
- Personal or otherwise sensitive column: `comment on column ... is 'sensitive: <why>'`, grant
  `app_rw` only the other columns, and read it through an audited definer function (`app.user_emails`).
- New privileges: `insert into app.privileges` and `app.role_privileges` for each role.
- Views: `with (security_invoker = true)`. No `security definer` unless unavoidable; then
  `set search_path = app, pg_temp`, add it to the allowlist in `invariants_test.go`, and say why.

- Every `unique`, `check`, foreign key or exclusion constraint `app_rw` can violate goes into
  `internal/api/constraints.go`: `constraintFields` (request field + message, e.g. a taken name)
  or `constraintsNotUserFacing` (why no input can reach it). Keep the default constraint names.
- A unique constraint on an existing table: `create unique index concurrently`, then
  `add constraint ... unique using index`, in a `-- +goose NO TRANSACTION` file (see 00006).

Fails if skipped: `TestDatabaseInvariants` (also for a missing `version` or a selectable sensitive column), `TestEveryConstraintIsMapped`, `make lint-migrations` (squawk); a changed applied migration fails `make migrations-immutable` in CI.

## 3. Queries (`internal/store/queries.sql`)

No authorization in `WHERE` clauses: RLS filters. Lists use keyset pagination like
`ListProjects` (`limit` plus `after_*` arguments). A text filter is one more `and` on the same
ordered query (`strpos(lower(col), lower(sqlc.arg(query)::text)) > 0`, no LIKE escaping), so the
page token stays correct; its proto field `query` gets `string.max_len`. Then `make generate`.

## 4. Contract (`proto/app/v1/*.proto`)

Every RPC gets `option (authz.v1.privilege) = "<privilege>"`. An RPC that changes who may do
what (roles, group mappings, anything under `access.manage` that writes) also gets
`option (authz.v1.max_auth_age) = 600;` (step-up: recent sign-in, at most 900 seconds); a new
read-only `access.manage` RPC goes into `stepUpExempt` in `contract_test.go` instead.

Every request field gets a `(buf.validate.field)` rule: ids `int64.gt = 0`, lengths and ranges
that match the table's `check` constraints (trimmed names: a `cel` rule with `this.trim()`, see
`CreateProjectRequest`), `string.email`, `string.in` or an enum for fixed sets. A field that truly
needs none says `ignore: IGNORE_ALWAYS`. The server enforces them in `NewHandler`; nothing to call.
List RPCs take `page_size` (`int32 = {gte: 0, lte: 100}`) and `page_token` and return
`next_page_token`. `buf lint` must pass. Then `make generate`.

Fails if skipped: `TestEveryMethodDeclaresPrivilege`, `TestDeclaredPrivilegesExistInCatalog`,
`TestAccessChangesNeedRecentSignIn`, `TestEveryRequestFieldHasRules`, `TestListsArePaginated`.

## 5. Handler (`internal/api/`)

Use `s.withUser(ctx, ...)` and `toConnect(ctx, err)`; never return database errors to the client.
Updates check the version the caller sent (`errStale` -> `Aborted`); a row the caller cannot
see or change stays `PermissionDenied`, so the answer never reveals that it exists.
Reuse `pageSize` / `encodePageToken` / `decodePageToken` for lists.

## 6. Access matrix (`docs/access-matrix.md`)

Add a row per new RPC (one per org for org-scoped calls) with a cell for every persona:
each role, a user of another org (RLS), not signed in. The table is the specification and
goes to the business owner for review; show it to the user. Then add the row's call to the
`calls` map in `internal/api/matrix_test.go`. Guards a table cannot show (self, escalation)
get a test like `access_guards_test.go`.

Fails if skipped: `TestRoleMatrix` (an RPC without a row, a row without a call, a wrong cell).

## 7. UI (`frontend/src/`)

Calls only through `src/lib/api.ts` (`hasPrivilege` for UI hints). Hide actions the user lacks
privileges for (a hint; the server decides). Forms show the server's violations at the field:
`const errors = fieldErrors(mutation.error)`, `{...invalidProps(errors.name, "name")}` on the
control and `<FieldError message={errors.name} id="name" />` under it; keep `errorMessage` in an
alert for everything else; database constraints mapped in `constraints.go` arrive the same way.
Don't repeat the proto rules in the UI. Lists: `usePagedList` (`src/lib/paged-list.ts`) and
`<DataTable>` (`src/components/data-table.tsx`) with typed columns, row actions and `filterLabel`
when the RPC takes `query`; columns hidden on phones get `className: "hidden sm:table-cell"`. Use the components in `src/components/ui`. No raw HTML. If a new dependency
needs raw HTML, `make e2e` reports a Trusted Types violation: add its exact string to
`src/trusted-types.ts` and say so in the PR (security review).

Extend `frontend/e2e/smoke.spec.ts` when the feature adds a main flow, and add each new screen,
dialog and select to `frontend/e2e/a11y.spec.ts` (axe; fix violations in the component).

## 8. Verify

`make check` and `make e2e`. Look at the screen in the browser (`make run`), on mobile width too.
