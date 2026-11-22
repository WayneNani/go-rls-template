# Access matrix

Who may do what. This table is the specification: `internal/api/matrix_test.go` reads it
and runs every cell against the real server (authz interceptor, store, Postgres RLS).

- Change a cell and the test checks the new expectation.
- Change the code or a migration without the table and the test fails.
- Every RPC needs at least one row, every row a call in the test.

Review changes to this file with the business owner of the app (CODEOWNERS).

## Personas

Seeded by the test, each in its own sign-in.

| Persona | Roles |
|---|---|
| anonymous | not signed in |
| nobody | signed in, no role anywhere |
| viewerAcme | viewer in Acme |
| editorAcme | editor in Acme |
| adminAcme | admin in Acme |
| editorGlobex | editor in Globex |

## Matrix

Cells: `allow`, `deny` (permission denied), `sign-in` (sign-in required). For lists,
`allow: Acme` also names the orgs whose rows the persona sees. Before each persona the test
gives the target user a `viewer` role in Acme and creates an IdP mapping in Acme, so the
revoke and remove rows act on rows that exist.

| Action | anonymous | nobody | viewerAcme | editorAcme | adminAcme | editorGlobex |
|---|---|---|---|---|---|---|
| WhoAmI | sign-in | allow | allow | allow | allow | allow |
| ListProjects | sign-in | deny | allow: Acme | allow: Acme | allow: Acme | allow: Globex |
| CreateProject in Acme | sign-in | deny | deny | allow | allow | deny |
| CreateProject in Globex | sign-in | deny | deny | deny | deny | allow |
| UpdateProject in Acme | sign-in | deny | deny | allow | allow | deny |
| UpdateProject in Globex | sign-in | deny | deny | deny | deny | allow |
| ListRoles | sign-in | allow | allow | allow | allow | allow |
| ListMembers of Acme | sign-in | deny | deny | deny | allow | deny |
| ListMembers of Globex | sign-in | deny | deny | deny | deny | deny |
| GrantRole editor in Acme | sign-in | deny | deny | deny | allow | deny |
| GrantRole editor in Globex | sign-in | deny | deny | deny | deny | deny |
| RevokeRole viewer in Acme | sign-in | deny | deny | deny | allow | deny |
| ListGroupMappings of Acme | sign-in | deny | deny | deny | allow | deny |
| AddGroupMapping in Acme | sign-in | deny | deny | deny | allow | deny |
| RemoveGroupMapping in Acme | sign-in | deny | deny | deny | allow | deny |

Not in this table, tested in `access_guards_test.go`: no changes to your own roles, no
granting beyond your own privileges, IdP-sourced roles are read-only.
`UpdateProject` with a version the caller did not read last fails with `aborted` (lost update);
a project the caller cannot see or change stays `deny` (`matrix_test.go`, "stale version").
