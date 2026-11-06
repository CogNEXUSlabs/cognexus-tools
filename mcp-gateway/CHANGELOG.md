# Changelog

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
