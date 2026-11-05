/**
 * The MCP server over stdio, with a fetch the test supplies. A sentinel key
 * is the only API key, and it must not come back in a result or a log line.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { FetchLike } from "../client.js";
import { currentCliVersion, enrollStateKey, recordEnroll, setStateDirectoryForTests } from "../state.js";
import { listenMcpHttp, serveMcpStdio, type McpConfig } from "./server.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const SENTINEL = "cnx_SENTINEL_mcp_key_9f3a7c1e";
const NPM_LATEST = "https://registry.npmjs.org/@cognexuslabs/grokbot-artzain/latest";
const ENV_KEYS = [
  "COGNEXUS_API_KEY",
  "MYAPP_API_KEY",
  "COGNEXUS_API_BASE_URL",
  "GROKBOT_AGENT_ID",
  "GROKBOT_INSTANCE",
  "COGNEXUS_AGENT_DID",
  "GROKBOT_ENROLL_TTL_HOURS",
];

const savedEnv = new Map<string, string | undefined>();
let stateDir = "";

beforeEach(() => {
  for (const key of ENV_KEYS) {
    savedEnv.set(key, process.env[key]);
    delete process.env[key];
  }
  stateDir = mkdtempSync(join(tmpdir(), "grokbot-mcp-"));
  setStateDirectoryForTests(stateDir);
});

afterEach(async () => {
  setStateDirectoryForTests(undefined);
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  if (stateDir) await rm(stateDir, { recursive: true, force: true }).catch(() => {});
});

function decision(outcome: string, id: string, reasons: string[], warnings?: Record<string, unknown>[]) {
  return {
    outcome,
    decision_id: id,
    audit_block_id: "block",
    contributing_agents: [],
    policy_bundle_version: "1",
    resolution_policy: "highest_severity",
    latency_ms: 1,
    reasons,
    ...(warnings ? { warnings } : {}),
  };
}

interface Rpc {
  id?: string | number | null;
  result?: {
    isError?: boolean;
    content?: Array<{ text?: string }>;
    structuredContent?: Record<string, unknown>;
    tools?: Array<{ name?: string }>;
    protocolVersion?: string;
  };
  error?: { code?: number; message?: string };
}

/**
 * npm may print a notice around the JSON, and the JSON is either one
 * packument or an array of them. The publish job uses npm 12, which prints
 * one object; older npm prints an array. Read the first value only.
 */
function firstJson(out: string): unknown {
  const arrayAt = out.indexOf("[");
  const objectAt = out.indexOf("{");
  const start = arrayAt < 0 ? objectAt : objectAt < 0 ? arrayAt : Math.min(arrayAt, objectAt);
  if (start < 0) throw new Error("npm pack did not print a file list");
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < out.length; i++) {
    const ch = out[i] ?? "";
    if (inString) {
      if (escape) escape = false;
      else if (ch === "\\") escape = true;
      else if (ch === "\"") inString = false;
      continue;
    }
    if (ch === "\"") inString = true;
    else if (ch === "[" || ch === "{") depth++;
    else if (ch === "]" || ch === "}") {
      depth--;
      if (depth === 0) return JSON.parse(out.slice(start, i + 1));
    }
  }
  throw new Error("npm pack JSON did not end");
}

function packedPaths(parsed: unknown): string[] {
  if (Array.isArray(parsed)) {
    if (parsed.length > 0 && parsed.every((row) => !!row && typeof row === "object" && "path" in row)) {
      return parsed.map((row) => String((row as { path?: unknown }).path ?? "").replace(/\\/g, "/"));
    }
    return parsed.flatMap((row) => packedPaths(row));
  }
  if (!parsed || typeof parsed !== "object") return [];
  if ("files" in parsed && Array.isArray((parsed as { files?: unknown }).files)) {
    return packedPaths((parsed as { files: unknown }).files);
  }
  // npm 12 prints one object keyed by the package name, and that value is the packument.
  return Object.values(parsed as Record<string, unknown>).flatMap((value) => packedPaths(value));
}

function toolBody(response: Rpc): { isError: boolean; body: Record<string, unknown> } {
  const result = response.result;
  const text = result?.content?.[0]?.text ?? "";
  const body = JSON.parse(text) as Record<string, unknown>;
  expect(result?.structuredContent).toEqual(body);
  return { isError: result?.isError === true, body };
}

function openStdio(fetchImpl: FetchLike, config: McpConfig = {
  apiKey: SENTINEL,
  baseUrl: "https://engine.test",
  baseUrlSource: "--base-url",
  agentDid: "bot-1",
  instance: "host-1",
}) {
  const input = new PassThrough();
  const output = new PassThrough();
  const logs: string[] = [];
  const pending: string[] = [];
  let waiter: ((line: string) => void) | undefined;
  let seen = "";
  let all = "";
  output.setEncoding("utf8");
  output.on("data", (chunk: string) => {
    all += chunk;
    seen += chunk;
    let nl = seen.indexOf("\n");
    while (nl >= 0) {
      const line = seen.slice(0, nl);
      seen = seen.slice(nl + 1);
      if (waiter) {
        const resolve = waiter;
        waiter = undefined;
        resolve(line);
      } else pending.push(line);
      nl = seen.indexOf("\n");
    }
  });
  const done = serveMcpStdio({
    input,
    output,
    config,
    fetchImpl,
    log: (msg) => logs.push(msg),
  });
  const next = (): Promise<string> => {
    const line = pending.shift();
    if (line !== undefined) return Promise.resolve(line);
    return new Promise((resolve) => {
      waiter = resolve;
    });
  };
  return {
    logs,
    done,
    input,
    stdout: () => all,
    async send(msg: unknown): Promise<Rpc> {
      const got = next();
      input.write(`${JSON.stringify(msg)}\n`);
      return JSON.parse(await got) as Rpc;
    },
    write(line: string): Promise<string> {
      const got = next();
      input.write(line.endsWith("\n") ? line : `${line}\n`);
      return got;
    },
  };
}

async function handshake(session: ReturnType<typeof openStdio>): Promise<void> {
  const init = await session.send({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0" } },
  });
  expect(init.result?.protocolVersion).toBe("2024-11-05");
  expect(init.error).toBeUndefined();
  session.input.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
}

describe("mcp stdio", () => {
  it("maps allow, deny and review, and fails closed when the engine cannot be reached", async () => {
    type Mode = "allow" | "deny" | "review" | "down" | "too-old";
    let mode: Mode = "allow";
    const calls: Array<{ url: string; headers: Record<string, string>; body?: string }> = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, headers: { ...init.headers }, body: init.body });
      if (mode === "down") {
        const err = new TypeError("fetch failed");
        (err as { cause?: unknown }).cause = Object.assign(new Error(SENTINEL), { code: "ECONNREFUSED" });
        throw err;
      }
      if (mode === "too-old") {
        return {
          ok: false,
          status: 422,
          json: async () => ({ detail: { code: "client_too_old", leak: SENTINEL } }),
          text: async () => SENTINEL,
        };
      }
      const sent = JSON.parse(init.body ?? "{}") as { action?: string };
      const outcome = mode === "allow" ? "allow" : mode === "review" ? "review" : "deny";
      const id = sent.action === "send" ? "dec-allow" : outcome === "review" ? "dec-review" : "dec-deny";
      const reasons = outcome === "allow" ? [] : outcome === "review" ? ["needs a person"] : ["policy refused"];
      const warnings = outcome === "allow"
        ? [{ warning: "client_update", latest: "9.9.9", upgrade_command: "Run grokbot-artzain upgrade." }]
        : undefined;
      return {
        ok: true,
        status: 200,
        json: async () => decision(outcome, id, reasons, warnings),
        text: async () => "",
      };
    };
    const session = openStdio(fetchImpl);
    await handshake(session);

    const ping = await session.send({ jsonrpc: "2.0", id: "p", method: "ping" });
    expect(ping.result).toEqual({});

    const listed = await session.send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(listed.result?.tools?.map((tool) => tool.name)).toEqual([
      "artzain_decide",
      "artzain_status",
      "artzain_review_status",
    ]);

    const unknown = await session.send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: SENTINEL, arguments: {} },
    });
    expect(toolBody(unknown).isError).toBe(true);
    expect(calls).toHaveLength(0);

    mode = "allow";
    const allow = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "artzain_decide",
        arguments: {
          tool: "send_email",
          arguments: { to: "a@example.com" },
          action: "send",
          cites_review: "rev-1",
          request_id: "req-1",
        },
      },
    }));
    expect(allow.isError).toBe(false);
    expect(allow.body).toEqual({
      outcome: "allow",
      decision_id: "dec-allow",
      reasons: [],
      next_step: "run",
      notice: "grokbot-artzain 9.9.9 is available. Run grokbot-artzain upgrade.",
    });
    const posted = JSON.parse(calls[0]?.body ?? "{}") as {
      action?: string;
      target?: string;
      payload?: string;
      request_id?: string;
      context?: { cites_review?: string };
      payload_kind?: string;
      surface?: string;
    };
    expect(calls[0]?.url).toBe("https://engine.test/api/v1/decisions");
    expect(calls[0]?.headers["X-Api-Key"]).toBe(SENTINEL);
    expect(posted.action).toBe("send");
    expect(posted.target).toBe("grokbot:tool:send");
    expect(JSON.parse(posted.payload ?? "{}")).toEqual({ tool: "send_email", arguments: { to: "a@example.com" } });
    expect(posted.request_id).toBe("req-1");
    expect(posted.context).toEqual({ cites_review: "rev-1" });
    expect(posted.payload_kind).toBe("tool_call");
    expect(posted.surface).toBe("grokbot");

    mode = "deny";
    const deny = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "artzain_decide", arguments: { tool: "drop_table", arguments: {} } },
    }));
    expect(deny.isError).toBe(true);
    expect(deny.body).toEqual({
      outcome: "deny",
      decision_id: "dec-deny",
      reasons: ["policy refused"],
      next_step: "do not run",
    });
    const denyBody = JSON.parse(calls[1]?.body ?? "{}") as { action?: string; target?: string };
    expect(denyBody.action).toBe("drop_table");
    expect(denyBody.target).toBe("grokbot:tool:drop_table");

    mode = "review";
    const review = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "artzain_decide", arguments: { tool: "hold", arguments: { id: "1" } } },
    }));
    expect(review.isError).toBe(true);
    expect(review.body).toEqual({
      outcome: "review",
      decision_id: "dec-review",
      reasons: ["needs a person"],
      next_step: "wait for review",
    });

    mode = "down";
    const down = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "artzain_decide", arguments: { tool: "send_email", arguments: {} } },
    }));
    expect(down.isError).toBe(true);
    expect(down.body.outcome).toBe("deny");
    expect(down.body.decision_id).toBe("");
    expect(down.body.next_step).toBe("do not run");
    expect(JSON.stringify(down.body)).toContain("failing closed");

    mode = "too-old";
    const old = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "artzain_decide", arguments: { tool: "send_email", arguments: {} } },
    }));
    expect(old.isError).toBe(true);
    expect(old.body.reasons).toEqual([
      "REFUSED: this grokbot-artzain is older than the minimum this account accepts. Run grokbot-artzain upgrade.",
    ]);

    const leaked = await session.write(SENTINEL);
    expect(leaked).not.toContain(SENTINEL);
    expect(JSON.parse(leaked)).toMatchObject({ error: { code: -32700, message: "parse error" } });

    const stdout = session.stdout();
    expect(stdout).not.toContain(SENTINEL);
    expect(session.logs.join("\n")).not.toContain(SENTINEL);
    session.input.end();
    await session.done;
  }, 30_000);

  it("refuses a tool call before initialize", async () => {
    const session = openStdio(async () => {
      throw new Error(SENTINEL);
    });
    const early = await session.send({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "artzain_status", arguments: {} },
    });
    expect(early.error?.message).toBe("server not initialized");
    expect(JSON.stringify(early)).not.toContain(SENTINEL);
    session.input.end();
    await session.done;
  });

  it("reports status without the key, and asks npm with no key header", async () => {
    const version = currentCliVersion();
    const base = "https://engine.test";
    await recordEnroll(enrollStateKey(base, SENTINEL, "bot-1"), version, new Date());
    const calls: Array<{ url: string; headers: Record<string, string> }> = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, headers: { ...init.headers } });
      return { ok: true, status: 200, json: async () => ({ version: "9.9.9" }), text: async () => "" };
    };
    const session = openStdio(fetchImpl);
    await handshake(session);
    const status = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "artzain_status", arguments: {} },
    }));
    expect(status.isError).toBe(false);
    expect(status.body.version).toBe(version);
    expect(status.body.agent_id).toBe("bot-1");
    expect(status.body.instance).toBe("host-1");
    expect(status.body.enroll).toEqual({
      state: "fresh",
      last_enroll_at: expect.any(String),
      cli_version: version,
    });
    expect(status.body.notice).toBe("grokbot-artzain 9.9.9 is available. Run grokbot-artzain upgrade.");
    expect(JSON.stringify(status.body)).not.toContain(SENTINEL);
    expect(calls.map((call) => call.url)).toEqual([NPM_LATEST]);
    expect(calls[0]?.headers["X-Api-Key"]).toBeUndefined();
    expect(JSON.stringify(calls[0]?.headers)).not.toContain(SENTINEL);
    expect(session.logs.join("\n")).not.toContain(SENTINEL);
    session.input.end();
    await session.done;
  });

  it("reads a review on the review route, and fails closed when that route cannot be reached", async () => {
    let fail = false;
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
      calls.push(url);
      if (fail) throw new TypeError(SENTINEL);
      return {
        ok: true,
        status: 200,
        json: async () => ({ decision_id: "dec-9", status: "pending" }),
        text: async () => "",
      };
    };
    const session = openStdio(fetchImpl);
    await handshake(session);
    const pending = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "artzain_review_status", arguments: { decision_id: "dec-9" } },
    }));
    expect(pending.isError).toBe(false);
    expect(pending.body).toEqual({ decision_id: "dec-9", status: "pending" });
    expect(calls).toEqual(["https://engine.test/api/v1/decisions/dec-9/review"]);

    fail = true;
    const down = toolBody(await session.send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "artzain_review_status", arguments: { decision_id: "dec-9" } },
    }));
    expect(down.isError).toBe(true);
    expect(JSON.stringify(down.body)).toContain("failing closed");
    expect(JSON.stringify(down.body)).not.toContain("approved");
    expect(JSON.stringify(down.body)).not.toContain(SENTINEL);
    expect(session.logs.join("\n")).not.toContain(SENTINEL);
    session.input.end();
    await session.done;
  });
});

describe("mcp http", () => {
  it("answers initialize, a notification and ping on 127.0.0.1", async () => {
    const logs: string[] = [];
    const listening = await listenMcpHttp({
      port: 0,
      config: { apiKey: SENTINEL },
      log: (msg) => logs.push(msg),
    });
    try {
      const url = `http://127.0.0.1:${listening.port}/`;
      const init = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2024-11-05" },
        }),
      });
      expect(init.status).toBe(200);
      const noted = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      });
      expect(noted.status).toBe(202);
      expect(await noted.text()).toBe("");
      const ping = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }),
      });
      expect(await ping.json()).toMatchObject({ result: {} });
      expect(logs.join("\n")).not.toContain(SENTINEL);
    } finally {
      await listening.close();
    }
  });
});

describe("plugin files", () => {
  it("keeps plugin/SKILL.md identical to SKILL.md", () => {
    const skill = readFileSync(join(root, "SKILL.md"));
    const plugin = readFileSync(join(root, "plugin", "SKILL.md"));
    expect(Buffer.compare(skill, plugin)).toBe(0);
  });

  it("names the unknown manifest format and the four settings", () => {
    const manifest = JSON.parse(readFileSync(join(root, "plugin", "manifest.json"), "utf8")) as {
      todo?: string;
      settings?: Array<{ name?: string; secret?: boolean; optional?: boolean }>;
    };
    expect(manifest.todo).toContain("Q1");
    expect(manifest.todo).toContain("was not found");
    const settings = new Map((manifest.settings ?? []).map((row) => [row.name, row]));
    expect(settings.get("COGNEXUS_API_KEY")?.secret).toBe(true);
    expect(settings.has("GROKBOT_AGENT_ID")).toBe(true);
    expect(settings.has("GROKBOT_INSTANCE")).toBe(true);
    expect(settings.get("COGNEXUS_API_BASE_URL")?.optional).toBe(true);
  });

  it("includes plugin/ in the packed files", () => {
    const out = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: root,
      encoding: "utf8",
      windowsHide: true,
      shell: process.platform === "win32",
    });
    const paths = packedPaths(firstJson(out));
    expect(paths.some((path) => path.endsWith("plugin/manifest.json"))).toBe(true);
    expect(paths.some((path) => path.endsWith("plugin/SKILL.md"))).toBe(true);
  }, 60_000);
});
