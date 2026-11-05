/**
 * One upstream MCP session, over a child process or an HTTP POST.
 * Stderr from a child, and response headers from an HTTP server, can carry
 * a token. This module reads them only to keep the pipes moving, and it
 * never writes them out.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

import type { UpstreamConfig } from "./config.js";

const PROTOCOL = "2024-11-05";
const CLIENT = { name: "artzain-mcp-gateway", version: "0.1.0" };

export interface RpcMessage {
  jsonrpc?: string;
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code?: number; message?: string };
}

export class UpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UpstreamError";
  }
}

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "Path", "PATHEXT", "SYSTEMROOT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", "TEMP", "TMP"]) {
    const value = process.env[key];
    if (value) env[key] = value;
  }
  for (const [key, value] of Object.entries(extra)) env[key] = value;
  return env;
}

export class StdioUpstream {
  private child: ChildProcessWithoutNullStreams | undefined;
  private pending = new Map<number, { resolve: (message: RpcMessage) => void; reject: (err: Error) => void }>();
  private nextId = 1;
  private readonly command: string[];
  private readonly env: Record<string, string>;

  constructor(config: UpstreamConfig) {
    this.command = config.command ?? [];
    this.env = config.env ?? {};
  }

  async start(): Promise<void> {
    if (this.child) return;
    const [file, ...args] = this.command;
    if (!file) throw new UpstreamError("the upstream command is empty");
    const child = spawn(file, args, { stdio: ["pipe", "pipe", "pipe"], env: childEnv(this.env), windowsHide: true });
    this.child = child;
    child.stderr.on("data", () => undefined);
    child.on("error", (err) => this.failAll(new UpstreamError(`the upstream process failed (${err.name})`)));
    child.on("exit", () => this.failAll(new UpstreamError("the upstream process exited")));
    const lines = createInterface({ input: child.stdout });
    lines.on("line", (line) => this.takeLine(line));
    await this.request("initialize", {
      protocolVersion: PROTOCOL,
      capabilities: {},
      clientInfo: CLIENT,
    });
    this.notify("notifications/initialized");
  }

  async listTools(): Promise<unknown[]> {
    const result = await this.request("tools/list", {});
    const tools = (result as { tools?: unknown }).tools;
    if (!Array.isArray(tools)) throw new UpstreamError("the upstream tools list is not an array");
    return tools;
  }

  async callTool(name: string, args: unknown): Promise<unknown> {
    return this.request("tools/call", { name, arguments: args ?? {} });
  }

  close(): void {
    this.child?.kill();
    this.child = undefined;
  }

  private notify(method: string): void {
    this.child?.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method })}\n`);
  }

  private request(method: string, params: unknown): Promise<unknown> {
    const child = this.child;
    if (!child) return Promise.reject(new UpstreamError("the upstream is not running"));
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new UpstreamError("the upstream timed out"));
      }, 10_000);
      this.pending.set(id, {
        resolve: (message) => {
          clearTimeout(timer);
          if (message.error) {
            const code = message.error.code ?? -1;
            reject(new UpstreamError(`the upstream rejected the call (${code})`));
            return;
          }
          resolve(message.result);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  private takeLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;
    let message: RpcMessage;
    try {
      message = JSON.parse(trimmed) as RpcMessage;
    } catch {
      return;
    }
    if (typeof message.id !== "number") return;
    const waiter = this.pending.get(message.id);
    if (!waiter) return;
    this.pending.delete(message.id);
    waiter.resolve(message);
  }

  private failAll(err: Error): void {
    for (const waiter of this.pending.values()) waiter.reject(err);
    this.pending.clear();
    this.child = undefined;
  }
}

export class HttpUpstream {
  private session: string | undefined;
  private nextId = 1;
  private started = false;
  private readonly url: string;
  private readonly headers: Record<string, string>;

  constructor(config: UpstreamConfig) {
    this.url = config.url ?? "";
    this.headers = config.headers ?? {};
  }

  async start(): Promise<void> {
    if (this.started) return;
    await this.request("initialize", {
      protocolVersion: PROTOCOL,
      capabilities: {},
      clientInfo: CLIENT,
    });
    await this.post({ jsonrpc: "2.0", method: "notifications/initialized" });
    this.started = true;
  }

  async listTools(): Promise<unknown[]> {
    const result = await this.request("tools/list", {});
    const tools = (result as { tools?: unknown }).tools;
    if (!Array.isArray(tools)) throw new UpstreamError("the upstream tools list is not an array");
    return tools;
  }

  async callTool(name: string, args: unknown): Promise<unknown> {
    return this.request("tools/call", { name, arguments: args ?? {} });
  }

  close(): void {
    this.started = false;
  }

  private async request(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId;
    this.nextId += 1;
    const message = await this.post({ jsonrpc: "2.0", id, method, params });
    if (message.error) {
      const code = message.error.code ?? -1;
      throw new UpstreamError(`the upstream rejected the call (${code})`);
    }
    return message.result;
  }

  private async post(body: unknown): Promise<RpcMessage> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...this.headers,
    };
    if (this.session) headers["mcp-session-id"] = this.session;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    let response: Response;
    try {
      response = await fetch(this.url, {
        method: "POST",
        redirect: "manual",
        signal: controller.signal,
        headers,
        body: JSON.stringify(body),
      });
    } catch (err) {
      const name = err && typeof err === "object" && "name" in err ? String((err as { name: string }).name) : "Error";
      throw new UpstreamError(`the upstream is unreachable (${name})`);
    } finally {
      clearTimeout(timer);
    }
    if (response.status >= 300 && response.status < 400) {
      throw new UpstreamError("the upstream redirected the call");
    }
    const session = response.headers.get("mcp-session-id");
    if (session) this.session = session;
    if (!response.ok) {
      throw new UpstreamError(`the upstream rejected the call (HTTP ${response.status})`);
    }
    const type = response.headers.get("content-type") ?? "";
    const text = await response.text();
    const payload = type.includes("text/event-stream")
      ? text.split("\n").find((line) => line.startsWith("data: "))?.slice(6)
      : text;
    if ((body as { id?: unknown }).id === undefined && !type.includes("text/event-stream")) return {};
    if (!payload) throw new UpstreamError("the upstream returned an empty event stream");
    try {
      return JSON.parse(payload) as RpcMessage;
    } catch {
      throw new UpstreamError("the upstream returned a response that is not JSON");
    }
  }
}

export type Upstream = StdioUpstream | HttpUpstream;

export function openUpstream(config: UpstreamConfig): Upstream {
  return config.command ? new StdioUpstream(config) : new HttpUpstream(config);
}
