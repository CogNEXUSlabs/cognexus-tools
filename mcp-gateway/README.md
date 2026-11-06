# ArtzAIn MCP gateway

`@cognexuslabs/artzain-mcp-gateway` is an MCP server. It proxies the MCP servers listed in `gateway.json`. CogNEXUS Labs publishes it beside the TypeScript SDK and the OpenClaw, n8n, and Grok Bot packages.

A client sees one tool list. Each tool name is `<upstream>__<tool>`. `tools/call` asks the ArtzAIn Decision API before it forwards anything. The action and the target come from the W15 taxonomy shipped in this package (`src/taxonomy.json`). An entry in the upstream's `tools` map replaces the action for that tool name. The payload `tool` field is the action the rule matches.

Only an `allow` is forwarded. A `deny`, a `review`, an unrecognised outcome, a missing API key, and a Decision API outage all return `isError` and the upstream is not called. A review includes the decision id:

```text
QUEUED FOR REVIEW: this call needs human approval before it runs.
(decision <id>)
```

A deny includes the reason. An outage says the decision is unavailable and that the gateway is failing closed. There is no offline path.

Connectors which Grok Bot authenticates with its own OAuth may not be routable through the gateway. The first release targets self-hosted and API-key MCP servers.

## Configure

```json
{
  "upstreams": [
    {
      "name": "notes",
      "agent_id": "notes-bot",
      "command": ["node", "server.js"],
      "env": { "API_TOKEN": "set-this-outside-the-repo" },
      "tools": { "save_doc": "write_file" }
    }
  ]
}
```

Each upstream has a `name`, an `agent_id`, and exactly one of `command` (a string array) or `url` (http or https). `headers` and `env` are sent to that upstream and are not written to the gateway log. `tools` maps a raw tool name to an action.

The gateway reads `--config`, then `ARTZAIN_GATEWAY_CONFIG`, then `./gateway.json`. The Decision API key is `COGNEXUS_API_KEY`. `COGNEXUS_API_BASE_URL` defaults to `https://app.cognexuslabs.ai`. A child-process upstream does not inherit the gateway's environment, so its token belongs in that upstream's `env`.

```bash
npm install -g @cognexuslabs/artzain-mcp-gateway
artzain-mcp-gateway --config gateway.json
```

From a checkout, `node dist/cli.js --config gateway.json` is the same command.

Point an MCP client at that process over stdio. Logs stay on stderr, and stderr does not include upstream credentials or the API key.

## Action log

Each `tools/call` the gateway forwards after an allow appends one JSON line to `ARTZAIN_GATEWAY_LOG`, or by default `~/.config/artzain-mcp-gateway/gateway.jsonl` (on Windows, `%APPDATA%\artzain-mcp-gateway\gateway.jsonl`):

```json
{"at":"2026-11-06T01:02:03.456Z","agent":"notes-bot","action":"write_file","target":"file:path/notes.txt","decision_id":"<decision id>"}
```

`grokbot-artzain coverage --since <ISO time>` reads this file. A call the gateway refuses is not forwarded and gets no line. The line holds no arguments, headers, env values or key. If the file cannot be written, the gateway says so on stderr and forwards the call anyway.

## Develop

From this directory: `npm ci`, `npm test`, `npm run build`. It publishes from the public mirror on an `mcp-gateway-v<version>` tag.
