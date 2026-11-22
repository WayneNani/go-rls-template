# All developer and CI commands. `make check` is what CI and the Claude Stop hook run.
GO_TOOL := go tool -modfile=tools/go.mod
# Tools whose dependencies clash with golangci-lint live in their own modules.
GITLEAKS   := go tool -modfile=tools/gitleaks/go.mod gitleaks
ACTIONLINT := go tool -modfile=tools/actionlint/go.mod actionlint
# One pnpm version for everything: the packageManager field in frontend/package.json.
PNPM_VERSION := $(shell sed -n 's/.*"packageManager": "pnpm@\([^"]*\)".*/\1/p' frontend/package.json)
PNPM    ?= npx --yes pnpm@$(PNPM_VERSION)
DB      := localhost:55433
BASE    ?= origin/main

export TEST_DATABASE_ADMIN_URL ?= postgres://postgres:postgres@$(DB)/postgres?sslmode=disable
export DATABASE_URL            ?= postgres://app_rw:app_rw@$(DB)/app?sslmode=disable
export MIGRATE_DATABASE_URL    ?= postgres://app_owner:app_owner@$(DB)/app?sslmode=disable

# Local only: plain-HTTP cookies, unencrypted DB, the mock IdP from compose.yaml. The IdP
# runs on 127.0.0.1 and the app on localhost: two sites, so the login is a real cross-site
# redirect and SameSite problems show up in development, not first in production.
DEV_ENV := INSECURE_DEV=true OIDC_ISSUER=http://127.0.0.1:8091/default \
           OIDC_CLIENT_ID=starter OIDC_CLIENT_SECRET=dev-secret

.PHONY: up up-otel down setup init frontend-deps migrate seed generate lint lint-rules lint-migrations secrets \
        migrations-immutable test e2e e2e-clean vuln check web run dev dev-api dev-web scaffold

up:
	docker compose up -d --wait

# Also the Jaeger trace UI (http://127.0.0.1:16686); see "Debugging a request" in README.md.
up-otel:
	docker compose --profile otel up -d --wait

down:
	docker compose --profile otel down

setup: up frontend-deps
	git config core.hooksPath .githooks
	$(MAKE) migrate seed web

# Make the starter your project: make init MODULE=github.com/acme/portal NAME="Acme Portal"
init:
	PNPM="$(PNPM)" scripts/init.sh "$(MODULE)" "$(NAME)"

frontend-deps:
	cd frontend && $(PNPM) install --frozen-lockfile

migrate:
	INSECURE_DEV=true go run ./cmd/migrate

seed:
	docker compose exec -T db psql -q -U postgres -d app -v ON_ERROR_STOP=1 < dev/seed.sql

# New org-scoped entity in every layer (migration, queries, proto, handler, matrix, UI, E2E),
# as plain code you own: make scaffold NAME=invoice FIELDS="title:text amount:int due:date paid:bool"
# Optional PLURAL=... when adding "s" is wrong. Then: make generate check migrate.
scaffold:
	go run ./cmd/scaffold -name '$(NAME)' -fields '$(FIELDS)' -plural '$(PLURAL)'

generate:
	$(GO_TOOL) buf generate
	$(GO_TOOL) sqlc generate

lint: lint-rules lint-migrations
	$(GO_TOOL) buf lint
	$(GO_TOOL) golangci-lint run ./...
	$(ACTIONLINT)
	cd frontend && $(PNPM) typecheck && $(PNPM) lint

# Rules a linter config cannot express.
lint-rules:
	@if grep -rnE 'nolint:[a-z,]*(depguard|forbidigo|gosec)' --include=*.go cmd internal; then \
		echo 'nolint for depguard, forbidigo or gosec is not allowed'; exit 1; fi
	@if grep -rn 'INSECURE_DEV' Dockerfile compose.yaml .github; then \
		echo 'INSECURE_DEV belongs to the local dev targets in this Makefile only'; exit 1; fi

# Dangerous locking in migrations (squawk, pinned in frontend/package.json, no install script).
# Only the Up part: a Down section drops on purpose. 00001-00004 predate the linter (immutable).
# goose wraps each file in a transaction unless it says `+goose NO TRANSACTION`.
SQUAWK := frontend/node_modules/.bin/squawk --pg-version 18 --reporter gcc
lint-migrations:
	@for f in $(filter-out $(wildcard internal/store/migrations/0000[1-4]_*.sql),$(wildcard internal/store/migrations/*.sql)); do \
		tx=$$(grep -q '^-- +goose NO TRANSACTION' $$f || echo --assume-in-transaction); \
		sed '/^-- +goose Down/,$$d' $$f | $(SQUAWK) $$tx --stdin-filepath $$f || exit 1; done

# Applied migrations never change; a fix is a new migration. CI compares with the PR base.
migrations-immutable:
	@changed=$$(git diff --name-only --diff-filter=MDR $(BASE)...HEAD -- internal/store/migrations); \
	if [ -n "$$changed" ]; then echo "Applied migrations changed, add a new one instead:"; echo "$$changed"; exit 1; fi

# Secrets in the git history (the pre-commit hook checks staged changes).
secrets:
	$(GITLEAKS) git --redact --no-banner

test:
	go test -race -count=1 ./...

# Browser smoke test: sign-in, roles, dialog, no CSP or Trusted Types violation.
e2e: up migrate seed web
	(cd frontend && $(PNPM) exec playwright test); status=$$?; $(MAKE) e2e-clean; exit $$status

# Rows the browser tests create (names start with "E2E "), removed after every run.
e2e-clean:
	docker compose exec -T db psql -q -U postgres -d app -v ON_ERROR_STOP=1 < dev/e2e-clean.sql

vuln:
	$(GO_TOOL) govulncheck ./...
	cd frontend && $(PNPM) audit --prod --audit-level high

check: generate lint test

web:
	cd frontend && $(PNPM) build
	touch internal/web/dist/.gitkeep

run: web
	$(DEV_ENV) OIDC_REDIRECT_URL=http://localhost:8090/auth/callback go run ./cmd/server

# Hot reload: Vite on http://localhost:5173 in front of the Go server.
dev:
	$(MAKE) -j2 dev-api dev-web

dev-api:
	$(DEV_ENV) LISTEN_ADDR=127.0.0.1:8090 OIDC_REDIRECT_URL=http://localhost:5173/auth/callback go run ./cmd/server

dev-web:
	cd frontend && $(PNPM) dev
