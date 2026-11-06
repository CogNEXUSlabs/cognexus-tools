/**
 * End to end: a fake upstream and a fake Decision API. Allow is the only
 * outcome that reaches the upstream. Deny, review, and an outage do not.
 */

import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const API_KEY = "gateway-test-key";
const UPSTREAM_TOKEN = "super-secret-token";

interface RpcResponse {
  id?: number;
  result?: {
    tools?: { name: string }[];
    serverInfo?: { name?: string; version?: string };
    isError?: boolean;
    content?: { type: string; text: string }[];
  };
  error?: { message?: string };
}

interface SeenDecision {
  body: {
    action?: string;
    target?: string;
    agent_did?: string;
    payload?: string;
    payload_kind?: string;
    surface?: string;
    product?: string;
  };
  sawKey: boolean;
}

let dir: string;
let decisions: Server;
let decisionPort = 0;
let decisionOpen = true;
let mode: "allow" | "deny" | "review" = "allow";
const seen: SeenDecision[] = [];
let gateway: ChildProcessWithoutNullStreams;
let stderr = "";
let served: { name?: string; version?: string } | undefined;
let nextId = 1;
const pending = new Map<number, (message: RpcResponse) => void>();

function request(method: string, params?: unknown): Promise<RpcResponse> {
  const id = nextId;
  nextId += 1;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${method}`)), 8000);
    pending.set(id, (message) => {
      clearTimeout(timer);
      resolve(message);
    });
    gateway.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
}

async function callLog(): Promise<string> {
  return readFile(join(dir, "calls.log"), "utf8").catch(() => "");
}

/** The gateway's action log, as `grokbot-artzain coverage` reads it. */
async function actionLines(): Promise<{ raw: string; row: Record<string, unknown> }[]> {
  const text = await readFile(join(dir, "logs", "gateway.jsonl"), "utf8").catch(() => "");
  return text.split("\n").filter((line) => line.trim()).map((raw) => ({ raw, row: JSON.parse(raw) as Record<string, unknown> }));
}

beforeAll(async () => {
  execFileSync(process.execPath, ["node_modules/typescript/bin/tsc", "-p", "tsconfig.json"], {
    cwd: ROOT,
    stdio: "inherit",
  });
  execFileSync(process.execPath, ["scripts/copy-taxonomy.mjs"], { cwd: ROOT, stdio: "inherit" });

  dir = await mkdtemp(join(tmpdir(), "artzain-gateway-"));
  const upstream = join(dir, "upstream.mjs");
  await writeFile(upstream, `import { createInterface } from "node:readline";
import { appendFileSync } from "node:fs";
const log = process.argv[2];
const lines = createInterface({ input: process.stdin });
function send(message) { process.stdout.write(JSON.stringify(message) + "\\n"); }
lines.on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  if (msg.id === undefined) return;
  if (msg.method === "initialize") {
    appendFileSync(log + ".clients", JSON.stringify(msg.params.clientInfo) + "\\n");
    send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "0" } } });
  } else if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "write_file", description: "Write a file", inputSchema: { type: "object" } }] } });
  } else if (msg.method === "tools/call") {
    appendFileSync(log, JSON.stringify(msg.params) + "\\n");
    send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "wrote the file" }] } });
  } else {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
  }
});
`);
  await writeFile(join(dir, "gateway.json"), JSON.stringify({
    upstreams: [{
      name: "notes",
      agent_id: "notes-bot",
      command: [process.execPath, upstream, join(dir, "calls.log")],
      env: { UPSTREAM_TOKEN },
      tools: {},
    }],
  }));

  decisions = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as SeenDecision["body"];
      seen.push({ body, sawKey: req.headers["x-api-key"] === API_KEY });
      const outcome = mode;
      const decisionId = outcome === "review" ? "dec-review-7" : "dec-allow-1";
      const reasons = outcome === "deny" ? ["policy denied this call"] : [];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ outcome, decision_id: decisionId, reasons }));
    });
  });
  await new Promise<void>((resolve) => decisions.listen(0, "127.0.0.1", resolve));
  decisionPort = (decisions.address() as { port: number }).port;

  gateway = spawn(process.execPath, [join(ROOT, "dist", "cli.js"), "--config", join(dir, "gateway.json")], {
    cwd: ROOT,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    env: {
      PATH: process.env.PATH,
      Path: process.env.Path,
      PATHEXT: process.env.PATHEXT,
      SYSTEMROOT: process.env.SYSTEMROOT,
      SystemRoot: process.env.SystemRoot,
      COMSPEC: process.env.COMSPEC,
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
      COGNEXUS_API_KEY: API_KEY,
      COGNEXUS_API_BASE_URL: `http://127.0.0.1:${decisionPort}`,
      ARTZAIN_GATEWAY_LOG: join(dir, "logs", "gateway.jsonl"),
    },
  });
  gateway.stderr.setEncoding("utf8");
  gateway.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const lines = createInterface({ input: gateway.stdout });
  lines.on("line", (line) => {
    const message = JSON.parse(line) as RpcResponse;
    const waiter = typeof message.id === "number" ? pending.get(message.id) : undefined;
    if (waiter && typeof message.id === "number") {
      pending.delete(message.id);
      waiter(message);
    }
  });
}, 20000);

afterAll(async () => {
  gateway?.kill();
  if (decisionOpen && decisions) {
    await new Promise<void>((resolve) => decisions.close(() => resolve()));
  }
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("a fake upstream", () => {
  it("lists the upstream tool under the upstream prefix", async () => {
    const init = await request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "0" },
    });
    expect(init.result).toBeTruthy();
    served = init.result?.serverInfo;
    gateway.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    const listed = await request("tools/list");
    expect(listed.result?.tools?.map((tool) => tool.name)).toEqual(["notes__write_file"]);
  });

  it("forwards an allow and records the taxonomy action", async () => {
    mode = "allow";
    const response = await request("tools/call", {
      name: "notes__write_file",
      arguments: { path: "notes.txt" },
    });
    expect(response.result?.isError).not.toBe(true);
    expect(response.result?.content?.[0]?.text).toBe("wrote the file");
    const log = await callLog();
    expect(log).toContain("write_file");
    expect(log).toContain("notes.txt");
    const decision = seen.at(-1);
    expect(decision?.sawKey).toBe(true);
    expect(decision?.body.action).toBe("write_file");
    expect(decision?.body.target).toBe("file:path/notes.txt");
    expect(decision?.body.agent_did).toBe("notes-bot");
    expect(decision?.body.payload_kind).toBe("tool_call");
    expect(decision?.body.surface).toBe("mcp");
    expect(JSON.parse(decision?.body.payload ?? "{}")).toMatchObject({
      tool: "write_file",
      arguments: { path: "notes.txt" },
    });
    const lines = await actionLines();
    expect(lines).toHaveLength(1);
    const { raw, row } = lines[0]!;
    expect(Object.keys(row).sort()).toEqual(["action", "agent", "at", "decision_id", "target"]);
    expect(row).toMatchObject({
      agent: "notes-bot",
      action: "write_file",
      target: "file:path/notes.txt",
      decision_id: "dec-allow-1",
    });
    expect(String(row.at)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/);
    expect(raw).not.toContain("arguments");
    expect(raw).not.toContain(API_KEY);
    expect(raw).not.toContain(UPSTREAM_TOKEN);
  });

  it("reports the version in package.json to the client, the Decision API and the upstream", async () => {
    const { version } = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8")) as { version: string };
    expect(served).toEqual({ name: "artzain-mcp-gateway", version });
    expect(seen.at(-1)?.body.product).toBe(`artzain-mcp-gateway@${version}`);
    const clients = (await readFile(join(dir, "calls.log.clients"), "utf8")).trim().split("\n");
    expect(clients.length).toBeGreaterThan(0);
    for (const line of clients) {
      expect(JSON.parse(line)).toEqual({ name: "artzain-mcp-gateway", version });
    }
  });

  it("blocks a deny without calling the upstream", async () => {
    mode = "deny";
    const before = await callLog();
    const response = await request("tools/call", {
      name: "notes__write_file",
      arguments: { path: "denied.txt" },
    });
    expect(response.result?.isError).toBe(true);
    expect(response.result?.content?.[0]?.text).toContain("REFUSED:");
    expect(response.result?.content?.[0]?.text).toContain("policy denied this call");
    expect(await callLog()).toBe(before);
    expect(await actionLines()).toHaveLength(1);
  });

  it("blocks a review and returns the decision id", async () => {
    mode = "review";
    const before = await callLog();
    const response = await request("tools/call", {
      name: "notes__write_file",
      arguments: { path: "review.txt" },
    });
    const text = response.result?.content?.[0]?.text ?? "";
    expect(response.result?.isError).toBe(true);
    expect(text).toContain("QUEUED FOR REVIEW:");
    expect(text).toContain("(decision dec-review-7)");
    expect(await callLog()).toBe(before);
    expect(await actionLines()).toHaveLength(1);
  });

  it("forwards an allow when the action log cannot be written", async () => {
    mode = "allow";
    await rm(join(dir, "logs"), { recursive: true, force: true });
    await writeFile(join(dir, "logs"), "not a directory");
    const response = await request("tools/call", {
      name: "notes__write_file",
      arguments: { path: "unlogged.txt" },
    });
    expect(response.result?.isError).not.toBe(true);
    expect(response.result?.content?.[0]?.text).toBe("wrote the file");
    expect(await callLog()).toContain("unlogged.txt");
    expect(stderr).toContain("could not record the action");
    expect(stderr).not.toContain(API_KEY);
    await rm(join(dir, "logs"), { force: true });
  });

  it("blocks an outage without calling the upstream", async () => {
    const before = await callLog();
    decisionOpen = false;
    await new Promise<void>((resolve) => decisions.close(() => resolve()));
    const response = await request("tools/call", {
      name: "notes__write_file",
      arguments: { path: "outage.txt" },
    });
    const text = response.result?.content?.[0]?.text ?? "";
    expect(response.result?.isError).toBe(true);
    expect(text).toContain("REFUSED:");
    expect(text).toContain("Failing closed.");
    expect(await actionLines()).toHaveLength(0);
    expect(text).not.toContain(API_KEY);
    expect(text).not.toContain(UPSTREAM_TOKEN);
    expect(await callLog()).toBe(before);
    expect(stderr).not.toContain(API_KEY);
    expect(stderr).not.toContain(UPSTREAM_TOKEN);
  });
});
