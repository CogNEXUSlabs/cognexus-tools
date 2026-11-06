/**
 * The gateway speaks MCP on stdin and stdout. A tools/call is forwarded only
 * when the Decision API returns allow. Every other outcome, including an
 * outage, is isError and the upstream is not called.
 */

import { createInterface } from "node:readline";

import { ConfigError, loadConfig, type GatewayConfig, type UpstreamConfig } from "./config.js";
import { decide, DecisionError, type Decision } from "./decide.js";
import { classifyTool } from "./taxonomy.js";
import { openUpstream, UpstreamError, type Upstream } from "./upstream.js";
import { VERSION } from "./version.js";

const PROTOCOL = "2024-11-05";

interface ToolCall {
  upstream: UpstreamConfig;
  tool: string;
}

function textResult(text: string, isError: boolean): unknown {
  return { content: [{ type: "text", text }], isError };
}

function stringArgs(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
      out[key] = String(item);
    }
  }
  return out;
}

function refusal(decision: Decision): string {
  const id = decision.decisionId ? `\n(decision ${decision.decisionId})` : "";
  if (decision.outcome === "review") {
    return `QUEUED FOR REVIEW: this call needs human approval before it runs.${id}`;
  }
  if (decision.outcome === "deny") {
    const reasons = decision.reasons.length > 0 ? decision.reasons.join("; ") : "policy denied this call";
    return `REFUSED: ${reasons}${id}`;
  }
  return `REFUSED: unrecognised outcome ${JSON.stringify(decision.outcome)}. Failing closed.${id}`;
}

export class Gateway {
  private readonly sessions = new Map<string, Upstream>();

  constructor(private readonly config: GatewayConfig) {}

  async listTools(): Promise<unknown> {
    const tools = [];
    for (const upstream of this.config.upstreams) {
      let listed: unknown[];
      try {
        listed = await this.session(upstream).then((session) => session.listTools());
      } catch (err) {
        const kind = err instanceof UpstreamError ? err.message : "the upstream could not be listed";
        throw new UpstreamError(`upstream ${upstream.name}: ${kind}`);
      }
      for (const tool of listed) {
        if (!tool || typeof tool !== "object") continue;
        const row = tool as { name?: unknown; description?: unknown; inputSchema?: unknown };
        if (typeof row.name !== "string" || row.name === "") continue;
        tools.push({
          name: `${upstream.name}__${row.name}`,
          description: typeof row.description === "string" ? row.description : "",
          inputSchema: row.inputSchema ?? { type: "object" },
        });
      }
    }
    return { tools };
  }

  async callTool(name: string, args: unknown): Promise<unknown> {
    const routed = this.route(name);
    if (!routed) return textResult(`Unknown tool ${JSON.stringify(name)}.`, true);
    const override = routed.upstream.tools[routed.tool];
    const classified = classifyTool(routed.tool, stringArgs(args));
    const action = override || classified.action;
    const payload = JSON.stringify({ tool: action, arguments: args ?? {} });
    let decision: Decision;
    try {
      decision = await decide({
        agentId: routed.upstream.agentId,
        action,
        target: classified.target,
        payload,
      });
    } catch (err) {
      const message = err instanceof DecisionError ? err.message : "decision unavailable (Error). Failing closed.";
      return textResult(`REFUSED: ${message}`, true);
    }
    if (decision.outcome !== "allow") return textResult(refusal(decision), true);
    try {
      const session = await this.session(routed.upstream);
      const result = await session.callTool(routed.tool, args ?? {});
      if (result && typeof result === "object") return result;
      return textResult("the upstream returned an empty result", true);
    } catch (err) {
      const message = err instanceof UpstreamError ? err.message : "the upstream call failed";
      return textResult(`FAILED: ${message}`, true);
    }
  }

  close(): void {
    for (const session of this.sessions.values()) session.close();
    this.sessions.clear();
  }

  private route(name: string): ToolCall | undefined {
    const upstream = this.config.upstreams.find((row) => name.startsWith(`${row.name}__`));
    if (!upstream) return undefined;
    const tool = name.slice(upstream.name.length + 2);
    if (tool === "") return undefined;
    return { upstream, tool };
  }

  private async session(upstream: UpstreamConfig): Promise<Upstream> {
    const existing = this.sessions.get(upstream.name);
    if (existing) return existing;
    const opened = openUpstream(upstream);
    try {
      await opened.start();
    } catch (err) {
      opened.close();
      throw err;
    }
    this.sessions.set(upstream.name, opened);
    return opened;
  }
}

interface RpcRequest {
  jsonrpc?: string;
  id?: number | string | null;
  method?: string;
  params?: unknown;
}

function reply(id: number | string | null | undefined, result: unknown): string {
  return `${JSON.stringify({ jsonrpc: "2.0", id: id ?? null, result })}\n`;
}

function fail(id: number | string | null | undefined, code: number, message: string): string {
  return `${JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } })}\n`;
}

export async function handleRequest(gateway: Gateway, request: RpcRequest): Promise<string | undefined> {
  const { id, method, params } = request;
  if (method === "notifications/initialized" || method === "notifications/cancelled") return undefined;
  if (id === undefined) return undefined;
  if (method === "initialize") {
    return reply(id, {
      protocolVersion: PROTOCOL,
      capabilities: { tools: {} },
      serverInfo: { name: "artzain-mcp-gateway", version: VERSION },
    });
  }
  if (method === "ping") return reply(id, {});
  if (method === "tools/list") {
    try {
      return reply(id, await gateway.listTools());
    } catch (err) {
      const message = err instanceof UpstreamError ? err.message : "the tool list failed";
      return fail(id, -32000, message);
    }
  }
  if (method === "tools/call") {
    const row = (params ?? {}) as { name?: unknown; arguments?: unknown };
    if (typeof row.name !== "string") return fail(id, -32602, "tools/call needs a tool name");
    return reply(id, await gateway.callTool(row.name, row.arguments));
  }
  return fail(id, -32601, "Method not found");
}

export async function serve(config: GatewayConfig, input: NodeJS.ReadableStream, output: NodeJS.WritableStream): Promise<void> {
  const gateway = new Gateway(config);
  const stop = () => gateway.close();
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  process.on("exit", stop);
  const lines = createInterface({ input });
  for await (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let request: RpcRequest;
    try {
      request = JSON.parse(trimmed) as RpcRequest;
    } catch {
      output.write(fail(null, -32700, "Parse error"));
      continue;
    }
    const response = await handleRequest(gateway, request);
    if (response) output.write(response);
  }
  gateway.close();
}

export async function run(argv: string[]): Promise<number> {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("artzain-mcp-gateway --config gateway.json\n");
    return 0;
  }
  const flag = argv.indexOf("--config");
  const path = flag >= 0 ? argv[flag + 1] : process.env.ARTZAIN_GATEWAY_CONFIG || "gateway.json";
  if (!path) {
    process.stderr.write("a config path is required\n");
    return 2;
  }
  let config: GatewayConfig;
  try {
    config = loadConfig(path);
  } catch (err) {
    const message = err instanceof ConfigError ? err.message : "cannot read the gateway config";
    process.stderr.write(`${message}\n`);
    return 2;
  }
  await serve(config, process.stdin, process.stdout);
  return 0;
}
