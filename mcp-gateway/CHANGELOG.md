# Changelog

## 0.1.4

### Added

- **What an upstream returns is decided before the client sees it.** After a forwarded call, the gateway sends the text of the result (its text parts, the text of embedded resources, resource links and structured content) for a second decision, with `payload_kind` `external_content` and the same `session_id`, agent, action and target as the call. Only an `allow` returns the result, exactly as the upstream sent it. A `deny`, a `review`, an unrecognised outcome and an outage return `isError` with `REFUSED: the upstream result was not returned.`, the reasons and the decision id. The call has already run by then: the refusal keeps its output away from the model and does not undo the call. 0.1.3 returned every result unread.

### Changed

- A forwarded call whose result holds text asks for two decisions, and both are sealed and metered. A result with no text (an image, audio, an empty reply) asks for one, as before.
- A result with more than 256 KiB of text, an embedded binary resource, or a part of a type the gateway does not know is refused without a second decision.

## 0.1.3

### Added

- **Each decision carries the gateway's session.** One gateway process serves one client connection, and every decision it asks for carries the same `session_id` (`mcp:<uuid>`, made when the process starts). The engine signs it into the decision's record, and a decision trace groups the run's tool calls by it. Nothing to configure. The gateway names no parent decision.

## 0.1.2

### Added

- **An action log for `grokbot-artzain coverage`.** Each `tools/call` the gateway forwards after an allow appends one JSON line (`at`, `agent`, `action`, `target`, `decision_id`) to `ARTZAIN_GATEWAY_LOG`, or by default `~/.config/artzain-mcp-gateway/gateway.jsonl` (`%APPDATA%\artzain-mcp-gateway\gateway.jsonl` on Windows), the file `coverage` reads. A refused call gets no line, because it never reaches the upstream. The line holds no arguments, headers, env values or key. When the file cannot be written, the gateway prints `artzain-mcp-gateway could not record the action` on stderr and forwards the call. 0.1.1 wrote no log, so the gateway source of `coverage` was always empty.

### Changed

- The README gives the npm install command and documents the action log.

## 0.1.1

### Changed

- The first release that `publish-npm.yml` publishes from the cognexus-tools mirror, with npm provenance. 0.1.0 was published once by hand so that npm could bind the trusted publisher, and it has no provenance.
- The gateway reports the version in its `package.json`: as its MCP `serverInfo`, as the client it opens each upstream with, and in each decision's `product`. 0.1.0 had `0.1.0` written in each of those places.
- `bin` names `dist/cli.js` without `./`. `npm publish` rewrote `./dist/cli.js` and printed that it had removed the command, though it had kept it.

## 0.1.0

### Added

- An MCP gateway that lists upstream tools as `<upstream>__<tool>` and forwards `tools/call` only when the Decision API returns allow. A deny, a review, and an outage return `isError` and do not call the upstream.
