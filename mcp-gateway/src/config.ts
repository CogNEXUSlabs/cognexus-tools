/**
 * gateway.json lists the upstream MCP servers this process proxies.
 * A header or env value is a credential. Nothing in this module prints it.
 */

import { readFileSync } from "node:fs";

export interface UpstreamConfig {
  name: string;
  agentId: string;
  command?: string[];
  url?: string;
  headers?: Record<string, string>;
  env?: Record<string, string>;
  tools: Record<string, string>;
}

export interface GatewayConfig {
  upstreams: UpstreamConfig[];
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$/;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

function stringMap(value: unknown, label: string): Record<string, string> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ConfigError(`${label} must be an object of strings`);
  }
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (typeof item !== "string" || item.length === 0) {
      throw new ConfigError(`${label}.${key} must be a non-empty string`);
    }
    out[key] = item;
  }
  return out;
}

function oneUpstream(value: unknown, index: number): UpstreamConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ConfigError(`upstreams[${index}] must be an object`);
  }
  const row = value as Record<string, unknown>;
  const name = row.name;
  const agentId = row.agent_id;
  if (typeof name !== "string" || !NAME.test(name)) {
    throw new ConfigError(`upstreams[${index}].name must match ${NAME.source}`);
  }
  if (typeof agentId !== "string" || agentId.trim() === "") {
    throw new ConfigError(`upstreams[${index}].agent_id must be a non-empty string`);
  }
  const command = row.command;
  const url = row.url;
  const hasCommand = command !== undefined;
  const hasUrl = url !== undefined;
  if (hasCommand === hasUrl) {
    throw new ConfigError(`upstreams[${index}] needs exactly one of command or url`);
  }
  let parsedCommand: string[] | undefined;
  let parsedUrl: string | undefined;
  if (hasCommand) {
    if (!Array.isArray(command) || command.length === 0 || command.some((part) => typeof part !== "string" || part === "")) {
      throw new ConfigError(`upstreams[${index}].command must be a non-empty array of strings`);
    }
    parsedCommand = command;
  } else {
    if (typeof url !== "string" || url.trim() === "") {
      throw new ConfigError(`upstreams[${index}].url must be a non-empty string`);
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new ConfigError(`upstreams[${index}].url is not a URL`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new ConfigError(`upstreams[${index}].url must be http or https`);
    }
    parsedUrl = url;
  }
  return {
    name,
    agentId: agentId.trim(),
    command: parsedCommand,
    url: parsedUrl,
    headers: stringMap(row.headers, `upstreams[${index}].headers`),
    env: stringMap(row.env, `upstreams[${index}].env`),
    tools: stringMap(row.tools, `upstreams[${index}].tools`),
  };
}

export function parseConfig(text: string): GatewayConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new ConfigError("gateway.json is not JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ConfigError("gateway.json must be an object");
  }
  const upstreams = (parsed as { upstreams?: unknown }).upstreams;
  if (!Array.isArray(upstreams) || upstreams.length === 0) {
    throw new ConfigError("upstreams must be a non-empty array");
  }
  const rows = upstreams.map((row, index) => oneUpstream(row, index));
  const names = rows.map((row) => row.name);
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      const left = names[i] ?? "";
      const right = names[j] ?? "";
      if (left === right || left.startsWith(`${right}_`) || right.startsWith(`${left}_`)) {
        throw new ConfigError(`upstream names ${left} and ${right} overlap as tool prefixes`);
      }
    }
  }
  return { upstreams: rows };
}

export function loadConfig(path: string): GatewayConfig {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? "unreadable";
    throw new ConfigError(`cannot read the gateway config (${code})`);
  }
  return parseConfig(text);
}
