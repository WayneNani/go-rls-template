#!/usr/bin/env bash
# Turns the starter into your project: Go module path and the app name in the UI.
# Usage: make init MODULE=github.com/acme/portal NAME="Acme Portal"
set -euo pipefail
module="${1:-}"
name="${2:-}"
if [[ -z "$module" || -z "$name" ]]; then
  echo 'usage: make init MODULE=github.com/acme/portal NAME="Acme Portal"' >&2
  exit 2
fi
cd "$(dirname "$0")/.."

old=example.com/starter
# Sources only. Generated code embeds the module path in binary descriptors, where a
# text replace corrupts them, so it is regenerated below instead.
grep -rlI --exclude-dir={.git,node_modules,dist,gen} "$old" . |
  grep -v '^./internal/store/db/' |
  xargs perl -pi -e "s{\Q$old\E}{$module}g"

export NAME="$name"
perl -pi -e 's{<title>Starter</title>}{<title>$ENV{NAME}</title>}' frontend/index.html
perl -pi -e 's{^(\s*)Starter$}{$1$ENV{NAME}}' frontend/src/App.tsx
perl -pi -e 's{^# go-rls-template$}{# $ENV{NAME}}' README.md

make -s frontend-deps generate
# Runs every package's init code (descriptor registration) without the DB tests.
go test -count=1 -run '^$' ./... >/dev/null
echo "Renamed to $module ($name). Next: replace @your-org in .github/CODEOWNERS, then make setup."
