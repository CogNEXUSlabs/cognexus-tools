# Changelog

All notable changes to `@cognexuslabs/grokbot-artzain`. Headings are the
bare version (`## 0.1.0`): the mirror's `publish-npm.yml` cuts the GitHub
release notes for tag `grokbot-v<version>` from the matching section.

## 0.1.2

Published 2026-09-18. Version-only for the first release through npm
Trusted Publishing (OIDC, Sigstore provenance), which also exercised the
`grokbot-v*` path of the mirror's publish workflow. `0.1.1` was the owner
bootstrap and has no attestation. Package README now installs from npm.

## 0.1.1

### Added

- **Pull enroll** (default on): `grokbot-artzain enroll` and the first
  gated `decide` call POST identity (`source: "grokbot"`) to
  `POST /api/v1/registry/enroll`. The reply names the adapter and never
  returns a `cnxe_` unless `--enroll-token` / `GROKBOT_ENROLL_TOKEN` is
  set. Fire-and-forget on `decide`; never blocks the Decision gate.
  `GROKBOT_ENROLL=false` or `--no-enroll` skips it.

## 0.1.0

### Added

- Cooperative Decision gate (`gateToolCall` / `grokbot-artzain decide`)
  for Grok Bot side-effects. There is no host `before_tool_call`
  intercept; fail-closed only when the skill runs.
- Opt-in announce (`source: "grokbot"`) so laptop hosts no scanner can
  reach still enter the Agent Wrangler review queue.
