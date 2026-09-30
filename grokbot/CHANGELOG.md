# Changelog

All notable changes to `@cognexuslabs/grokbot-artzain`. Headings are the
bare version (`## 0.1.0`): the mirror's `publish-npm.yml` cuts the GitHub
release notes for tag `grokbot-v<version>` from the matching section.

## 0.1.5

### Fixed

- **`grokbot-artzain decide` exits 0 or 2 on Windows.** With enroll or
  announce on (enroll is on by default), the CLI aborted as it exited,
  whatever the decision: it printed a libuv assertion (`Assertion failed:
  !(handle->flags & UV_HANDLE_CLOSING)`) and ended with exit code
  3221226505. Only the JSON it printed on stdout was right. A caller that
  treats any exit but 0 as a block, as `SKILL.md` says to, blocked allowed
  calls too; one that looked for exit 2 alone let denied calls through. The
  CLI no longer ends the process itself: it sets the exit code, ends the
  requests it no longer needs, and lets Node exit. The `announce` and
  `enroll` commands, which were not affected, now exit the same way.

### Changed

- `decide` prints the decision as soon as it has it, as before. An enroll
  or announce still running then gets up to 2 more seconds to finish and is
  then cut off, where the process used to end at once. Neither changes the
  exit code.

## 0.1.4

### Fixed

- **A redirect no longer takes the Decision API key to another host.**
  `gateToolCall`, `grokbot-artzain decide`, announce and enroll let `fetch`
  follow redirects, and `fetch` sends the request again, key included, to
  wherever a redirect points, another host included (after a 307 or 308,
  with its body). They no longer follow one. A 3xx on the Decision call
  blocks the tool call (fail closed) with a reason that names the status
  and the redirect; announce and enroll report it as a refusal and do not
  retry until the process restarts. Same fix as `@cognexuslabs/artzain`
  0.1.9, whose request types `client.ts` remains a verbatim copy of.
- **A failed request is reported without its error's text.** The block
  reason from `gateToolCall` (which `grokbot-artzain decide` prints),
  `postDecision()`'s `DecisionError`, and the announce and enroll log lines
  and results quoted the error `fetch` rejected with. That text can carry
  what a log must not: `fetch` quotes a header value it refuses, so an API
  key with a line break in it was quoted in full, and it quotes a base URL
  that holds a user name and password. They now name the error's kind (for
  `fetch`'s "fetch failed", its cause's, whose text is left out too: a
  certificate issued for another name puts the host in it) and where the
  base URL came from (skill config `baseUrl`, `--base-url` on the CLI,
  `COGNEXUS_API_BASE_URL` or the default), as in `decision unavailable
  (Decision API unreachable: Error [ECONNREFUSED] (base URL from
  COGNEXUS_API_BASE_URL)) — failing closed`. A 2xx answer that is not JSON
  is reported without the parser's text, which quotes the body, and a body
  that could not be read by the error's kind. Same fix as
  `@cognexuslabs/artzain` 0.1.9, whose response handling and `failureKind`
  `client.ts` copies verbatim.

### Changed

- A base URL the server redirects, `http://` to `https://` say, now blocks
  every gated call, where a 307 or 308 used to be followed once the key
  had gone out in cleartext: set it to the address the API answers on.
- Announce and enroll end the request on a refusal, whose body they do not
  read, so a large body no longer holds the connection until garbage
  collection.
- `FetchLike`, the type of the `fetchImpl` argument, now has a required
  `redirect: "manual"` in its request options, which every call passes.
  Code that calls a `FetchLike` itself must pass it too, and a fetch you
  pass must not follow redirects.

### Added

- `postDecision()` takes an optional `baseSource`, the label its message
  gives for where `baseUrl` came from (default "the baseUrl option"), and
  the skill config an optional `baseUrlSource`, the label for its `baseUrl`
  (default "skill config baseUrl"; the CLI sets `--base-url`).

## 0.1.3

### Fixed

- **The Decision API call times out while reading the response, not only
  while waiting for it.** The timer was cleared once the response headers
  arrived, so a server that sent them and then stopped mid-body left
  `gateToolCall` and `grokbot-artzain decide` waiting indefinitely. The
  deadline now covers the whole call, and a timeout blocks the tool call
  (fail closed) as any other engine error does. A body that could not be
  read says so instead of blaming a "non-JSON body". Same fix as
  `@cognexuslabs/artzain` 0.1.7, whose response handling `client.ts` remains
  a verbatim copy of.

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
