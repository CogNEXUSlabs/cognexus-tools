/**
 * `grokbot-artzain mcp`: a stdio MCP server, with an optional HTTP listener
 * on 127.0.0.1. initialize, tools/list, tools/call and ping are implemented
 * here so the package stays free of an MCP library.
 *
 * This server only sees calls made to artzain_decide. It does not run the
 * tool those calls describe. Anything but allow is a failed tool call. An
 * unreachable engine is a failed tool call too.
 *
 * stdout (and the HTTP body) is JSON-RPC. Notes go to the log, which the
 * command sends to stderr. The log names the method, never a key, a header
 * or the tool arguments.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import {
  DecisionError,
  failureKind,
  getReviewStatus,
  postDecision,
  resolveApiKey,
  resolveBaseUrlSetting,
  type DecisionResponse,
  type FetchLike,
} from "../client.js";
import {
  currentCliVersion,
  enrollIsFresh,
  enrollStateKey,
  enrollTtlMs,
  readEnrollState,
} from "../state.js";
import {
  INTERNAL_ERROR,
  INVALID_PARAMS,
  INVALID_REQUEST,
  METHOD_NOT_FOUND,
  PARSE_ERROR,
  parseRpc,
  rpcError,
  rpcResult,
  type RpcRequest,
  type RpcResponse,
} from "./jsonrpc.js";

const NPM_LATEST = "https://registry.npmjs.org/@cognexuslabs/grokbot-artzain/latest";
const LOGGED_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "ping",
  "tools/list",
  "tools/call",
]);
const CLIENT_TOO_OLD =
  "REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.";
const MAX_MESSAGE = 1_048_576;

export interface McpConfig {
  apiKey?: string;
  baseUrl?: string;
  baseUrlSource?: string;
  agentDid?: string;
  instance?: string;
}

export interface ServeOptions {
  config: McpConfig;
  fetchImpl?: FetchLike;
  log?: (msg: string) => void;
  env?: Record<string, string | undefined>;
  nowMs?: number;
}

interface Session {
  /** The client has sent initialize. */
  sawInitialize: boolean;
  /** The client has sent notifications/initialized. */
  ready: boolean;
}

const TOOLS = [
  {
    name: "artzain_decide",
    description:
      "Ask ArtzAIn whether a tool call may run. Returns outcome, decision_id, reasons, next_step, and notice when the engine sent one. Anything but allow is a failed tool call. This server does not run the tool. An unreachable engine fails closed.",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "The tool the caller would run." },
        arguments: { type: "object", description: "That tool's arguments." },
        action: { type: "string", description: "Decision action. Defaults to tool." },
        target: { type: "string", description: "Decision target. Defaults to grokbot:tool:<action>." },
        cites_review: { type: "string", description: "An approved review this call cites." },
        request_id: { type: "string", description: "Idempotency id. A replay returns the first decision." },
      },
      required: ["tool", "arguments"],
      additionalProperties: false,
    },
  },
  {
    name: "artzain_status",
    description:
      "This package's version, the agent id, the instance, the enroll state and an update notice. Never returns the API key.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "artzain_review_status",
    description:
      "Read pending, approved or rejected for a decision this account made. Does not change the review.",
    inputSchema: {
      type: "object",
      properties: {
        decision_id: { type: "string", description: "The decision to read." },
      },
      required: ["decision_id"],
      additionalProperties: false,
    },
  },
];

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function textField(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  if (!text || text.length > max) return undefined;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 32 || code === 127) return undefined;
  }
  return text;
}

function redact(text: string, secret: string | undefined): string {
  if (!secret) return text;
  return text.split(secret).join("[redacted]");
}

function redactValue(value: unknown, secret: string | undefined): unknown {
  if (!secret) return value;
  if (typeof value === "string") return redact(value, secret);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, secret));
  const row = asRecord(value);
  if (!row) return value;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(row)) out[redact(key, secret)] = redactValue(item, secret);
  return out;
}

function toolResult(body: Record<string, unknown>, isError: boolean, secret: string | undefined): unknown {
  const safe = redactValue(body, secret) as Record<string, unknown>;
  return {
    content: [{ type: "text", text: JSON.stringify(safe) }],
    structuredContent: safe,
    isError,
  };
}

function clientUpdateNotice(warnings: ReadonlyArray<Record<string, unknown>> | undefined): string | undefined {
  const row = (warnings ?? []).find((item) => item.warning === "client_update");
  if (!row) return undefined;
  const latest = typeof row.latest === "string" ? row.latest.trim() : "";
  const command = typeof row.upgrade_command === "string" ? row.upgrade_command.trim() : "";
  if (!latest && !command) return undefined;
  const available = latest
    ? `grokbot-artzain ${latest} is available`
    : "a newer grokbot-artzain is available";
  return command ? `${available}. ${command}` : available;
}

function isClientTooOld(err: unknown): boolean {
  if (!(err instanceof DecisionError) || err.status !== 422) return false;
  const detail = asRecord(err.detail);
  return detail?.code === "client_too_old";
}

function stringReasons(reasons: unknown): string[] {
  if (!Array.isArray(reasons)) return [];
  return reasons.filter((item): item is string => typeof item === "string");
}

function compareDot(left: string, right: string): number | null {
  const a = left.split(".");
  const b = right.split(".");
  if (a.some((part) => !/^\d+$/.test(part)) || b.some((part) => !/^\d+$/.test(part))) return null;
  const width = Math.max(a.length, b.length);
  for (let i = 0; i < width; i++) {
    const da = Number(a[i] ?? "0");
    const db = Number(b[i] ?? "0");
    if (da !== db) return da < db ? -1 : 1;
  }
  return 0;
}

function protocolVersion(params: unknown): string {
  const offered = asRecord(params)?.protocolVersion;
  return typeof offered === "string" && /^\d{4}-\d{2}-\d{2}$/.test(offered) ? offered : "2024-11-05";
}

function agentIdOf(config: McpConfig, env: Record<string, string | undefined>): string {
  return (config.agentDid || env.GROKBOT_AGENT_ID || env.COGNEXUS_AGENT_DID || "grokbot-agent").trim() || "grokbot-agent";
}

function instanceOf(config: McpConfig, env: Record<string, string | undefined>): string {
  return (config.instance || env.GROKBOT_INSTANCE || "").trim();
}

function closed(detail: string): Record<string, unknown> {
  return {
    outcome: "deny",
    decision_id: "",
    reasons: [`decision unavailable (${detail}) — failing closed`],
    next_step: "do not run",
  };
}

async function decideTool(
  args: Record<string, unknown>,
  options: ServeOptions,
  secret: string | undefined,
): Promise<unknown> {
  const tool = textField(args.tool, 200);
  const callArgs = asRecord(args.arguments);
  if (!tool || !callArgs) {
    return toolResult(closed("tool and arguments are required"), true, secret);
  }
  const action = textField(args.action, 200) ?? tool;
  const target = textField(args.target, 400) ?? `grokbot:tool:${action}`;
  const apiKey = resolveApiKey(options.config.apiKey);
  if (!apiKey) return toolResult(closed("No API key configured"), true, secret);
  const env = options.env ?? process.env;
  const base = resolveBaseUrlSetting(options.config.baseUrl, options.config.baseUrlSource);
  let payload: string;
  try {
    payload = JSON.stringify({ tool, arguments: callArgs });
  } catch {
    return toolResult(closed("the arguments could not be encoded"), true, secret);
  }
  try {
    const decision = await postDecision({
      apiKey,
      baseUrl: base.url,
      baseSource: base.source,
      action,
      target,
      payload,
      agentDid: agentIdOf(options.config, env),
      requestId: textField(args.request_id, 64),
      citesReview: textField(args.cites_review, 200),
      fetchImpl: options.fetchImpl,
    });
    return toolResult(decisionBody(decision), decision.outcome !== "allow", apiKey);
  } catch (err) {
    if (isClientTooOld(err)) {
      return toolResult(
        { outcome: "deny", decision_id: "", reasons: [CLIENT_TOO_OLD], next_step: "do not run" },
        true,
        apiKey,
      );
    }
    const detail = err instanceof DecisionError ? err.message : failureKind(err);
    return toolResult(closed(detail), true, apiKey);
  }
}

function decisionBody(decision: DecisionResponse): Record<string, unknown> {
  const outcome = decision.outcome;
  const known = outcome === "allow" || outcome === "deny" || outcome === "review";
  const reasons = stringReasons(decision.reasons);
  const body: Record<string, unknown> = {
    outcome: known ? outcome : "deny",
    decision_id: typeof decision.decision_id === "string" ? decision.decision_id : "",
    reasons: known
      ? reasons.length > 0 || outcome === "allow"
        ? reasons
        : [outcome === "review" ? "queued for review" : "policy denied this call"]
      : ["unrecognised outcome — failing closed"],
    next_step: outcome === "allow" ? "run" : outcome === "review" ? "wait for review" : "do not run",
  };
  const notice = clientUpdateNotice(decision.warnings);
  if (notice) body.notice = notice;
  return body;
}

async function statusTool(options: ServeOptions, secret: string | undefined): Promise<unknown> {
  const env = options.env ?? process.env;
  const version = currentCliVersion();
  const agentId = agentIdOf(options.config, env);
  const instance = instanceOf(options.config, env);
  const apiKey = resolveApiKey(options.config.apiKey);
  let enroll: Record<string, unknown>;
  if (!apiKey) {
    enroll = { state: "no_key" };
  } else {
    const base = resolveBaseUrlSetting(options.config.baseUrl, options.config.baseUrlSource);
    const saved = await readEnrollState();
    const entry = saved?.entries[enrollStateKey(base.url, apiKey, agentId)];
    const fresh = entry
      ? enrollIsFresh(entry, version, options.nowMs ?? Date.now(), enrollTtlMs(env.GROKBOT_ENROLL_TTL_HOURS))
      : false;
    enroll = entry
      ? { state: fresh ? "fresh" : "stale", last_enroll_at: entry.last_enroll_at, cli_version: entry.cli_version }
      : { state: "missing" };
  }
  const body: Record<string, unknown> = { version, agent_id: agentId, instance, enroll };
  const notice = await updateNotice(version, options.fetchImpl);
  if (notice) body.notice = notice;
  return toolResult(body, false, secret ?? apiKey);
}

async function updateNotice(version: string, fetchImpl: FetchLike | undefined): Promise<string | undefined> {
  const impl = fetchImpl ?? (globalThis.fetch as unknown as FetchLike | undefined);
  if (!impl) return undefined;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4_000);
  try {
    const resp = await impl(NPM_LATEST, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
      redirect: "manual",
    });
    if (!resp.ok) return undefined;
    const parsed = asRecord(await resp.json());
    const latest = typeof parsed?.version === "string" ? parsed.version.trim() : "";
    if (!latest) return undefined;
    const order = compareDot(version, latest);
    if (order === null || order >= 0) return undefined;
    return `grokbot-artzain ${latest} is available. Run grokbot-artzain upgrade.`;
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

async function reviewTool(
  args: Record<string, unknown>,
  options: ServeOptions,
  secret: string | undefined,
): Promise<unknown> {
  const decisionId = textField(args.decision_id, 200);
  if (!decisionId) return toolResult(closed("decision_id is required"), true, secret);
  const apiKey = resolveApiKey(options.config.apiKey);
  if (!apiKey) return toolResult(closed("No API key configured"), true, secret);
  const base = resolveBaseUrlSetting(options.config.baseUrl, options.config.baseUrlSource);
  try {
    const status = await getReviewStatus({
      apiKey,
      baseUrl: base.url,
      baseSource: base.source,
      decisionId,
      fetchImpl: options.fetchImpl,
    });
    return toolResult({ decision_id: status.decision_id, status: status.status }, false, apiKey);
  } catch (err) {
    const detail = err instanceof DecisionError ? err.message : failureKind(err);
    return toolResult(closed(detail), true, apiKey);
  }
}

async function callTool(name: string, args: Record<string, unknown>, options: ServeOptions): Promise<unknown> {
  const secret = resolveApiKey(options.config.apiKey);
  if (name === "artzain_decide") return decideTool(args, options, secret);
  if (name === "artzain_status") return statusTool(options, secret);
  if (name === "artzain_review_status") return reviewTool(args, options, secret);
  return toolResult({ error: "Unknown tool.", next_step: "do not run" }, true, secret);
}

async function handleRequest(request: RpcRequest, session: Session, options: ServeOptions): Promise<RpcResponse> {
  if (request.method === "ping") return rpcResult(request.id, {});
  if (request.method === "initialize") {
    session.sawInitialize = true;
    return rpcResult(request.id, {
      protocolVersion: protocolVersion(request.params),
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "grokbot-artzain", version: currentCliVersion() },
      instructions:
        "This server only sees calls made to artzain_decide. It does not run the tool and it does not see any other tool. Act only when artzain_decide returns outcome allow. Anything else means do not act.",
    });
  }
  if (!session.ready) return rpcError(request.id, INVALID_REQUEST, "server not initialized");
  if (request.method === "tools/list") return rpcResult(request.id, { tools: TOOLS });
  if (request.method === "tools/call") {
    const params = asRecord(request.params);
    const name = params && typeof params.name === "string" ? params.name : "";
    if (!params || !name) return rpcError(request.id, INVALID_PARAMS, "invalid params");
    const args = params.arguments === undefined ? {} : asRecord(params.arguments);
    if (!args) return rpcError(request.id, INVALID_PARAMS, "invalid params");
    return rpcResult(request.id, await callTool(name, args, options));
  }
  return rpcError(request.id, METHOD_NOT_FOUND, "method not found");
}

function note(options: ServeOptions): (msg: string) => void {
  const secret = resolveApiKey(options.config.apiKey);
  return (msg: string) => options.log?.(redact(msg, secret));
}

async function dispatch(line: string, session: Session, options: ServeOptions): Promise<RpcResponse | undefined> {
  const parsed = parseRpc(line);
  if (!parsed.ok) return rpcError(parsed.id, parsed.code, parsed.code === PARSE_ERROR ? "parse error" : "invalid request");
  const method = parsed.message.kind === "request" ? parsed.message.request.method : parsed.message.notification.method;
  const say = note(options);
  if (LOGGED_METHODS.has(method)) say(`grokbot-artzain mcp: ${method}`);
  if (parsed.message.kind === "notification") {
    if (method === "notifications/initialized" && session.sawInitialize) session.ready = true;
    return undefined;
  }
  try {
    return await handleRequest(parsed.message.request, session, options);
  } catch (err) {
    say(`grokbot-artzain mcp: ${failureKind(err)}`);
    return rpcError(parsed.message.request.id, INTERNAL_ERROR, "the call failed");
  }
}

/** A line that was too large to keep. Parsing it fails, and the bytes are not in the error. */
const DISCARDED = "\0";

async function* readLines(input: AsyncIterable<unknown>): AsyncGenerator<string> {
  let buffer = "";
  let discarding = false;
  const take = (text: string): string[] => {
    const out: string[] = [];
    buffer += text;
    let nl = buffer.indexOf("\n");
    while (nl >= 0) {
      const line = buffer.slice(0, nl).replace(/\r$/, "");
      buffer = buffer.slice(nl + 1);
      if (discarding || line.length > MAX_MESSAGE) {
        discarding = false;
        out.push(DISCARDED);
      } else if (line.trim()) {
        out.push(line);
      }
      nl = buffer.indexOf("\n");
    }
    if (buffer.length > MAX_MESSAGE) {
      buffer = "";
      discarding = true;
    }
    return out;
  };
  for await (const chunk of input) {
    const text = typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8");
    for (const line of take(text)) yield line;
  }
  if (discarding || buffer.length > MAX_MESSAGE) yield DISCARDED;
  else if (buffer.trim()) yield buffer;
}

export async function serveMcpStdio(options: ServeOptions & {
  input?: AsyncIterable<unknown>;
  output?: { write(chunk: string): unknown };
}): Promise<void> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const say = note(options);
  const session: Session = { sawInitialize: false, ready: false };
  for await (const line of readLines(input)) {
    let response: RpcResponse | undefined;
    try {
      response = await dispatch(line, session, options);
    } catch (err) {
      say(`grokbot-artzain mcp: ${failureKind(err)}`);
      response = rpcError(null, INTERNAL_ERROR, "the call failed");
    }
    if (response) output.write(`${JSON.stringify(response)}\n`);
  }
}

function tooLarge(line: string): boolean {
  return Buffer.byteLength(line) > MAX_MESSAGE;
}

async function readHttpBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += buf.length;
    if (size > MAX_MESSAGE) throw new Error("too large");
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

async function onHttp(req: IncomingMessage, res: ServerResponse, session: Session, options: ServeOptions): Promise<void> {
  if (req.method !== "POST") {
    sendJson(res, 405, rpcError(null, INVALID_REQUEST, "invalid request"));
    return;
  }
  let line: string;
  try {
    line = await readHttpBody(req);
  } catch {
    sendJson(res, 413, rpcError(null, INVALID_REQUEST, "invalid request"));
    return;
  }
  if (tooLarge(line)) {
    sendJson(res, 413, rpcError(null, INVALID_REQUEST, "invalid request"));
    return;
  }
  const response = await dispatch(line, session, options);
  if (!response) {
    res.writeHead(202);
    res.end();
    return;
  }
  sendJson(res, 200, response);
}

export interface ListeningMcp {
  port: number;
  close(): Promise<void>;
}

export function listenMcpHttp(options: ServeOptions & { port: number }): Promise<ListeningMcp> {
  const session: Session = { sawInitialize: false, ready: false };
  const server = createServer((req, res) => {
    void onHttp(req, res, session, options).catch((err: unknown) => {
      note(options)(`grokbot-artzain mcp: ${failureKind(err)}`);
      if (!res.headersSent) sendJson(res, 500, rpcError(null, INTERNAL_ERROR, "the call failed"));
      else res.end();
    });
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(options.port, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo | null;
      resolve({
        port: addr?.port ?? options.port,
        close: () => new Promise((done, fail) => server.close((err) => (err ? fail(err) : done()))),
      });
    });
  });
}

/** Listens until the process is stopped. The returned promise does not resolve. */
export async function serveMcpHttp(options: ServeOptions & { port: number }): Promise<void> {
  const listening = await listenMcpHttp(options);
  note(options)(`grokbot-artzain mcp: listening on 127.0.0.1:${listening.port}`);
  await new Promise(() => {});
}
