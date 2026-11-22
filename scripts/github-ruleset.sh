#!/usr/bin/env bash
# Creates two rulesets. Needs the gh CLI with admin rights on the
# repository. Run once after the first push:
#   scripts/github-ruleset.sh OWNER/REPO
#
# 1. Default branch: pull requests only, Code Owner review, every CI gate required (as
#    reported by GitHub Actions, app id 15368), no force push, no deletion.
# 2. Release tags v*: only repository admins may create, move or delete them. A tag runs
#    release.yml from the tagged commit, so an unprotected tag would sign unreviewed code.
#
# dependency-review is not required here: on private repositories it needs GitHub
# Advanced Security. Add {"context": "dependency-review", "integration_id": 15368} if
# the repository has it.
set -euo pipefail
repo="${1:?usage: scripts/github-ruleset.sh OWNER/REPO}"

gh api --method POST "repos/$repo/rulesets" --input - <<'JSON'
{
  "name": "default branch",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "require_code_owner_review": true,
        "dismiss_stale_reviews_on_push": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "check", "integration_id": 15368 },
          { "context": "image", "integration_id": 15368 },
          { "context": "e2e", "integration_id": 15368 },
          { "context": "secrets", "integration_id": 15368 },
          { "context": "workflows", "integration_id": 15368 }
        ]
      }
    }
  ]
}
JSON

gh api --method POST "repos/$repo/rulesets" --input - <<'JSON'
{
  "name": "release tags",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [{ "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [
    { "type": "creation" },
    { "type": "update" },
    { "type": "deletion" }
  ]
}
JSON
echo "Rulesets created. Also enable: secret scanning with push protection, Dependabot alerts, Renovate."
