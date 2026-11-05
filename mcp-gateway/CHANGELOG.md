# Changelog

## 0.1.0

### Added

- An MCP gateway that lists upstream tools as `<upstream>__<tool>` and forwards `tools/call` only when the Decision API returns allow. A deny, a review, and an outage return `isError` and do not call the upstream.
