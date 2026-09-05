# Changelog

All notable changes to `@cognexuslabs/artzain`. Headings are the bare
version (`## 0.1.5`): the mirror's `publish-npm.yml` cuts the GitHub release
notes for tag `sdk-ts-v<version>` from the matching section.

## 0.1.5

### Fixed

- **A non-JSON 2xx is a `DecisionError` now.** `decide()` and
  `fetchApiKeyIdentity()` returned `await resp.json()` straight from the
  response, so a proxy or captive portal answering `200 text/html` surfaced
  as a bare `SyntaxError` — outside the `DecisionError` contract callers
  filter on. Both now throw `DecisionError` with `status` set to the HTTP
  status (and no `detail`), the same way an error status does.
- `fetchApiKeyIdentity()` no longer sends `body: undefined as unknown as
  string` on its GET; `FetchLike`'s `body` is optional, which is what a GET
  looks like to a custom transport.

### Changed

- `errors.ts` and `decide.ts` carry `lockstep:begin` / `lockstep:end`
  markers around `DecisionError`, the response types and the response
  handling. The OpenClaw plugin ships a verbatim copy of those blocks (it
  has no runtime dependencies on purpose), and its test suite fails when the
  copy drifts from this package.

## 0.1.4

Published 2026-09-05.

### Added

- The `artzain login` profile (`~/.artzain/credentials.toml`, `[default]`
  table; `COGNEXUS_CREDENTIALS_PATH` overrides the path) is read after
  `configure()` and the environment, the way the Python SDK does it — the
  "run `artzain login`" advice in the missing-key error could not work
  before. Read through `process.getBuiltinModule("node:fs")`, so the module
  stays importable on other runtimes; on Node < 20.16 / 22.3 the profile is
  simply absent. `readProfile()` and `credentialsPath()` are exported.

### Fixed

- `postSdkEvent()` and `fetchApiKeyIdentity()` called `fetch` with no
  `AbortSignal`, so a stalled server left the call pending forever. Both
  take an optional `timeoutMs` (default 10 000); `postSdkEvent()` still
  returns `false` on abort and `fetchApiKeyIdentity()` throws
  `DecisionError`.

## 0.1.3

Published 2026-08-25 through npm Trusted Publishing. No API change
recorded — this changelog starts from the tree as imported that day.

## 0.1.2

Published 2026-08-22. First release through npm Trusted Publishing (OIDC,
Sigstore provenance; `npm audit signatures` verifies it). Registry
description cleaned up; no runtime change.

## 0.1.1

Published 2026-08-17. The default base URL moved to the app origin,
`https://app.cognexuslabs.ai`, so a fresh install resolves without
`COGNEXUS_API_BASE_URL`.

## 0.1.0

Published 2026-08-16 from `CogNEXUSlabs/cognexus-tools`. First release:
`configure()`, `decide()` (remote-only — a missing key throws
`DecisionError`, no offline guard), `postSdkEvent()` and
`fetchApiKeyIdentity()`; zero runtime dependencies, Node >= 18.
