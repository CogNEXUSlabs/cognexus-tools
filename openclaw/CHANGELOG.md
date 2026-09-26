# Changelog

All notable changes to `@cognexuslabs/openclaw-artzain`. Headings are the
bare version (`## 0.2.2`): the mirror's `publish-npm.yml` cuts the GitHub
release notes for tag `openclaw-v<version>` from the matching section.

## 0.2.6

### Changed

- README: install from npm, `openclaw plugins install
  @cognexuslabs/openclaw-artzain`, as the ClawHub listing already says. It
  said to install from a git checkout until a listing existed; a checkout
  install is now the route for an unreleased change.

### Fixed

- **The gate's Decision API call times out while reading the response, not
  only while waiting for it.** The timer was cleared once the response
  headers arrived, so a server that sent them and then stopped mid-body left
  the tool call waiting indefinitely. The deadline now covers the whole call,
  and a timeout blocks the tool (fail closed) as any other engine error does.
  A body that could not be read says so instead of blaming a "non-JSON
  body". Same fix as `@cognexuslabs/artzain` 0.1.7, whose response handling
  `client.ts` remains a verbatim copy of.

## 0.2.5

### Added

- **Pull enroll** (default on): on the first gated call the plugin POSTs
  identity (announce shape, names only) to `POST /api/v1/registry/enroll`
  with the Decision API key it already holds. The reply names the adapter
  to install and never returns a `cnxe_` unless `enrollToken` is set
  (one-shot grant from Govern / the snippet pack). Fire-and-forget; never
  blocks tool gating. Set `enroll: false` to skip.

## 0.2.4

### Changed

- README: the plugin configuration example's Decision API key sample reads
  `cnx_…`, the prefix every Decision API key has. It said `cgnx_…`. The code
  does not change.

## 0.2.3

### Fixed

- The Decision API types in `client.ts` match what the API sends.
  `AgentVote` is `name`, `verdict` (now a `DecisionOutcome`), `severity`,
  `score`, `findings` and `error`, where it declared `agent` and `reason`,
  which no response carries; `score` and `error` are `null` when unset.
  `DecisionResponse` gains the optional `warnings`. Same fix as
  `@cognexuslabs/artzain` 0.1.6, whose types these remain verbatim copies of.
  The gate's behaviour does not change.

## 0.2.2

Published 2026-09-05.

### Fixed

- **A non-JSON 2xx is a `DecisionError` now.** `postDecision()` returned
  `await resp.json()` straight from the response, so a proxy or captive
  portal answering `200 text/html` surfaced as a bare `SyntaxError`. The
  gate already failed closed on it (it blocks on any error); it now does so
  through the `DecisionError` branch, and the block reason names the HTTP
  status and the non-JSON body.
- The base-URL trailing-slash trim scans instead of using `/\/+$/`, which
  backtracked quadratically on a value made up mostly of slashes (the same
  fix the SDK's `config.ts` carries).

### Changed

- `DecisionResponse` matches the SDK's again (it had drifted to three
  fields; the server's `audit_block_id`, `contributing_agents`,
  `policy_bundle_version`, `resolution_policy` and `latency_ms` are typed
  now), and `FetchLike` gains `text()` with an optional `body`. Custom
  `fetchImpl` fakes in tests need the `text()` method.
- `DecisionError`, the response types and the response handling in
  `client.ts` are verbatim copies of `sdk/typescript/src/{errors,decide}.ts`
  between `lockstep:begin` / `lockstep:end` markers, and `lockstep.test.ts`
  fails when a copy drifts. The plugin deliberately still has no runtime
  dependency on `@cognexuslabs/artzain`: it is installed from a git checkout
  (`openclaw plugins install ./sdk/openclaw`) and loaded from `src/index.ts`
  with no install step, and each package is released from its own tag on the
  mirror with no ordering between them.

## 0.2.1

Published 2026-09-01.

### Fixed

- The announce log line now includes the server's `failed` count (rows that
  hit a server-side write error; a later announce retries them). It was
  built from four hardcoded keys, so an announce that stored nothing printed
  a clean-looking `registered 0, seen 0, blocked 0, deferred 0`. An older
  server without the key prints `failed 0`.

## 0.2.0

Published 2026-08-31.

### Added

- **Opt-in announce** (`announce: true`): the instance self-registers with
  the CogNEXUS Agent registry (`POST /api/v1/registry/announce`) from the
  first gated call, so instances no scanner can reach (laptops, home labs)
  still appear. Identity only — agent ids and skill slugs, never content —
  authenticated with the same Decision API key. Fire-and-forget: gating
  never waits on it and its failure never blocks. Attempt-once for
  successes and 4xx refusals; transient failures (network, 5xx, 429) re-arm
  for a later call. Prefers the hook's `agentId` so the announced identity
  matches the did stamped on decision leaves. Names are truncated on code
  points, not UTF-16 units, so an emoji on the boundary cannot produce the
  lone surrogate the server refuses.

## 0.1.1

Published 2026-08-27. Version-only: the first release through npm Trusted
Publishing (OIDC, Sigstore provenance), which also exercised the
`openclaw-v*` path of the mirror's publish workflow. No code change.

## 0.1.0

Published 2026-08-23 (bootstrap publish by hand; npm binds a trusted
publisher only to a package that already exists). First release: the
`before_tool_call` gate — `allow` runs the tool; `deny`, `review`, a missing
key and engine refusals (HTTP 503 / 401 / 422) return `{ block: true }`.
`review` is never mapped onto OpenClaw `/approve`.
