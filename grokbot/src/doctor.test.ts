/**
 * `grokbot-artzain doctor` reports the install. Each check is exercised
 * with an injected environment and fetch. Windows path lookups are stubbed,
 * so the suite does not depend on this machine's PATH or execution policy.
 * The sentinel key is a stand-in for a real one: it may be sent on the
 * enroll request, and it must not appear in any report.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import type { FetchLike } from "./client.js";
import { formatDoctorText, runDoctor, type DoctorCheck, type DoctorInput, type DoctorReport } from "./doctor.js";
import { enrollStateKey, keyFingerprint, type EnrollState } from "./state.js";

const here = dirname(fileURLToPath(import.meta.url));

const SENTINEL = "cnx_SENTINEL_doctor_key_9f3a7c1e";
const BASE = "https://engine.example";
const AGENT = "research-bot";
const VERSION = "0.1.10";
const NOW = Date.parse("2026-11-03T12:00:00.000Z");

type Call = { url: string; init: Parameters<FetchLike>[1] };

function freshState(): EnrollState {
  return {
    entries: {
      [enrollStateKey(BASE, SENTINEL, AGENT)]: {
        last_enroll_at: "2026-11-03T11:00:00.000Z",
        cli_version: VERSION,
      },
    },
  };
}

function okFetch(latest = VERSION): { impl: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const impl: FetchLike = async (url, init) => {
    calls.push({ url, init });
    if (url.includes("registry.npmjs.org")) {
      return { ok: true, status: 200, json: async () => ({ version: latest }), text: async () => "" };
    }
    if (url.endsWith("/health")) {
      return { ok: true, status: 200, json: async () => ({ status: "healthy" }), text: async () => "" };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({ adapter: { primary: "tool_gate" }, envelope: null }),
      text: async () => "",
    };
  };
  return { impl, calls };
}

function input(over: Partial<DoctorInput> = {}, fetch = okFetch()): DoctorInput & { calls: Call[] } {
  return {
    env: {},
    offline: true,
    platform: "linux",
    nodeVersion: "v20.11.0",
    engines: ">=18",
    path: "/usr/local/bin",
    exists: (file) => file === "/usr/local/bin/grokbot-artzain",
    cliVersion: VERSION,
    packageVersion: VERSION,
    skillText: `Skill text version: ${VERSION}\n`,
    apiKey: SENTINEL,
    baseUrl: BASE,
    agentId: AGENT,
    agentIdFromEnv: true,
    enrollEnabled: true,
    nowMs: NOW,
    readState: async () => freshState(),
    recordEnroll: async () => {},
    fetchImpl: fetch.impl,
    announceSkills: ["artzain"],
    instance: "ops-desk",
    calls: fetch.calls,
    ...over,
  };
}

function check(report: DoctorReport, name: string): DoctorCheck {
  const found = report.checks.find((item) => item.name === name);
  expect(found, name).toBeDefined();
  return found as DoctorCheck;
}

function rendered(report: DoctorReport): string {
  return `${formatDoctorText(report.checks)}\n${JSON.stringify(report)}`;
}

describe("formatDoctorText", () => {
  it("prints one bracket line per check and a fix under each that is not ok", () => {
    const text = formatDoctorText([
      { name: "node", status: "ok", summary: "node v20.11.0 meets engines >=18" },
      {
        name: "agent_id",
        status: "warn",
        summary: "GROKBOT_AGENT_ID is not set",
        fix: "Set GROKBOT_AGENT_ID to a stable name for this Bot. A Bot may pass --agent-did on each call.",
      },
      {
        name: "key",
        status: "fail",
        summary: "key is missing",
        fix: "Set COGNEXUS_API_KEY to a Decision API key (it starts with cnx_).",
      },
    ]);

    expect(text).toBe(
      [
        "  [ok ] node v20.11.0 meets engines >=18",
        "  [WARN] GROKBOT_AGENT_ID is not set",
        "        -> Set GROKBOT_AGENT_ID to a stable name for this Bot. A Bot may pass --agent-did on each call.",
        "  [FAIL] key is missing",
        "        -> Set COGNEXUS_API_KEY to a Decision API key (it starts with cnx_).",
      ].join("\n"),
    );
  });
});

describe("doctor checks", () => {
  it("reports every check, in order, and exits clean when all of them pass", async () => {
    const report = await runDoctor(input());

    expect(report.checks.map((item) => item.name)).toEqual([
      "node", "command", "cli", "skill", "key", "base_url", "key_accepted", "agent_id", "enroll_cache",
    ]);
    expect(report.checks.every((item) => item.status === "ok")).toBe(true);
    expect(report.ok).toBe(true);
  });

  it("fails when Node is older than engines", async () => {
    const report = await runDoctor(input({ nodeVersion: "v17.9.0" }));

    const node = check(report, "node");
    expect(node.status).toBe("fail");
    expect(node.fix).toContain("18");
    expect(report.ok).toBe(false);
  });

  it("accepts the engines minimum itself", async () => {
    const report = await runDoctor(input({ nodeVersion: "v18.0.0" }));

    expect(check(report, "node").status).toBe("ok");
  });

  it("fails when the command is not on PATH", async () => {
    const report = await runDoctor(input({ exists: () => false }));

    const command = check(report, "command");
    expect(command.status).toBe("fail");
    expect(command.fix).toContain("npm install -g");
    expect(command.fix).toContain("PATH");
  });

  it("looks up grokbot-artzain.cmd and the execution policy on Windows", async () => {
    const seen: string[] = [];
    let spawned = false;
    const report = await runDoctor(input({
      platform: "win32",
      path: "C:\\npm;C:\\Windows",
      exists: (file) => {
        seen.push(file);
        return file === "C:\\npm\\grokbot-artzain" || file === "C:\\npm\\grokbot-artzain.cmd";
      },
      executionPolicy: "RemoteSigned",
      readExecutionPolicy: () => {
        spawned = true;
        return "Restricted";
      },
    }));

    expect(check(report, "command").status).toBe("ok");
    expect(seen).toContain("C:\\npm\\grokbot-artzain.cmd");
    expect(seen.some((file) => file.includes("/"))).toBe(false);
    expect(spawned).toBe(false);
  });

  it("fails on Windows when grokbot-artzain.cmd is missing", async () => {
    const report = await runDoctor(input({
      platform: "win32",
      path: "C:\\npm",
      exists: (file) => file === "C:\\npm\\grokbot-artzain",
      executionPolicy: "RemoteSigned",
    }));

    const command = check(report, "command");
    expect(command.status).toBe("fail");
    expect(command.fix).toContain("grokbot-artzain.cmd");
  });

  it("warns on Windows when PowerShell refuses scripts and the .cmd shim is present", async () => {
    const report = await runDoctor(input({
      platform: "win32",
      path: "C:\\npm",
      exists: (file) => file === "C:\\npm\\grokbot-artzain" || file === "C:\\npm\\grokbot-artzain.cmd",
      executionPolicy: "Restricted",
    }));

    const command = check(report, "command");
    expect(command.status).toBe("warn");
    expect(command.fix).toContain("grokbot-artzain.cmd");
    expect(command.fix).toContain("Set-ExecutionPolicy -Scope CurrentUser RemoteSigned");
    expect(report.ok).toBe(true);
  });

  it("warns when this CLI is behind the latest on npm", async () => {
    const fetch = okFetch("0.1.12");
    const report = await runDoctor(input({ offline: false, fetchImpl: fetch.impl }, fetch));

    const cli = check(report, "cli");
    expect(cli.status).toBe("warn");
    expect(cli.summary).toContain("0.1.12");
    expect(cli.fix).toContain("npm install -g @cognexuslabs/grokbot-artzain");
    expect(fetch.calls.some((call) => call.url.includes("registry.npmjs.org"))).toBe(true);
    expect(report.ok).toBe(true);
  });

  it("skips the npm comparison with --offline", async () => {
    const fetch = okFetch("9.9.9");
    const report = await runDoctor(input({ offline: true, fetchImpl: fetch.impl }, fetch));

    expect(check(report, "cli").status).toBe("ok");
    expect(check(report, "cli").summary).toContain("--offline");
    expect(fetch.calls.some((call) => call.url.includes("registry.npmjs.org"))).toBe(false);
  });

  it("warns when the installed skill text version differs from the package", async () => {
    const report = await runDoctor(input({
      skillText: "Skill text version: 0.1.2\n",
      packageVersion: VERSION,
    }));

    const skill = check(report, "skill");
    expect(skill.status).toBe("warn");
    expect(skill.summary).toContain("0.1.2");
    expect(skill.fix).toContain(VERSION);
    expect(skill.fix).toContain("grokbot-artzain skill");
    expect(report.ok).toBe(true);
  });

  it("matches the skill text shipped in this package to package.json", async () => {
    const skillText = readFileSync(join(here, "..", "SKILL.md"), "utf8");
    const version = (JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string }).version;
    const report = await runDoctor(input({ skillText, packageVersion: version, cliVersion: version }));

    expect(check(report, "skill").status).toBe("ok");
  });

  it("prints a fingerprint of the key and never the key", async () => {
    const report = await runDoctor(input());
    const text = rendered(report);
    const full = keyFingerprint(SENTINEL);

    expect(check(report, "key").status).toBe("ok");
    expect(check(report, "key").summary).toContain(`sha256:${full.slice(0, 8)}`);
    expect(text).not.toContain(SENTINEL);
    expect(text).not.toContain(full);
  });

  it("fails the key check when MYAPP_API_KEY is the only name set", async () => {
    const lines: string[] = [];
    const write = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    try {
      const report = await runDoctor(input({
        apiKey: "",
        env: { MYAPP_API_KEY: "legacy-only-key" },
      }));
      expect(check(report, "key").status).toBe("fail");
      expect(rendered(report)).not.toContain("legacy-only-key");
      expect(lines.join("")).toContain("no key");
    } finally {
      process.stderr.write = write;
    }
  });

  it("treats COGNEXUS_AGENT_DID as the agent id when GROKBOT_AGENT_ID is unset", async () => {
    const report = await runDoctor(input({
      agentId: "from-did",
      agentIdFromEnv: undefined,
      env: { COGNEXUS_AGENT_DID: "from-did" },
    }));

    expect(check(report, "agent_id").status).toBe("ok");
    expect(check(report, "agent_id").summary).toContain("from-did");
  });

  it("fails when the key is missing", async () => {
    const fetch = okFetch();
    const report = await runDoctor(input({ apiKey: "", fetchImpl: fetch.impl }, fetch));

    expect(check(report, "key").status).toBe("fail");
    expect(check(report, "key").fix).toContain("COGNEXUS_API_KEY");
    expect(fetch.calls.some((call) => call.url.includes("/enroll"))).toBe(false);
    expect(report.ok).toBe(false);
    expect(rendered(report)).not.toContain(SENTINEL);
  });

  it("fails when the base URL redirects, and that probe carries no key", async () => {
    const calls: Call[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, init });
      const status = url.endsWith("/health") ? 302 : 200;
      return {
        ok: status === 200,
        status,
        json: async () => ({ adapter: { primary: "tool_gate" }, envelope: null }),
        text: async () => "",
      };
    };
    const report = await runDoctor(input({ fetchImpl }));

    const base = check(report, "base_url");
    expect(base.status).toBe("fail");
    expect(base.fix?.toLowerCase()).toContain("redirect");
    const probe = calls.find((call) => call.url.endsWith("/health"));
    expect(probe?.init.headers["X-Api-Key"]).toBeUndefined();
    expect(probe?.init.redirect).toBe("manual");
    expect(rendered(report)).not.toContain(SENTINEL);
    expect(report.ok).toBe(false);
  });

  it("accepts the key with the enroll request and never calls decide", async () => {
    const fetch = okFetch();
    const report = await runDoctor(input({ offline: false, fetchImpl: fetch.impl }, fetch));

    expect(check(report, "key_accepted").status).toBe("ok");
    const enroll = fetch.calls.filter((call) => call.url.includes("/api/v1/registry/enroll"));
    expect(enroll).toHaveLength(1);
    expect(enroll[0]?.init.method).toBe("POST");
    expect(enroll[0]?.init.redirect).toBe("manual");
    expect(enroll[0]?.init.headers["X-Api-Key"]).toBe(SENTINEL);
    expect(JSON.parse(enroll[0]?.init.body ?? "")).toEqual({
      source: "grokbot",
      instance: "ops-desk",
      agents: [AGENT],
      skills: ["artzain"],
    });
    expect(fetch.calls.some((call) => call.url.includes("/decisions"))).toBe(false);
    expect(rendered(report)).not.toContain(SENTINEL);
  });

  it("does not redeem an enroll token while it checks the key", async () => {
    const fetch = okFetch();
    const report = await runDoctor(input({
      env: { GROKBOT_ENROLL_TOKEN: "one-time-token-value" },
      fetchImpl: fetch.impl,
    }, fetch));

    const enroll = fetch.calls.find((call) => call.url.includes("/enroll"));
    const body = JSON.parse(enroll?.init.body ?? "{}") as { enroll_token?: string };
    expect(body.enroll_token).toBeUndefined();
    expect(rendered(report)).not.toContain("one-time-token-value");
  });

  it("fails when enroll refuses the key", async () => {
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.endsWith("/health")) {
        return { ok: true, status: 200, json: async () => ({}), text: async () => "" };
      }
      return { ok: false, status: 401, json: async () => ({ detail: init.headers["X-Api-Key"] }), text: async () => "" };
    };
    const report = await runDoctor(input({ fetchImpl }));

    const accepted = check(report, "key_accepted");
    expect(accepted.status).toBe("fail");
    expect(accepted.summary).toContain("401");
    expect(rendered(report)).not.toContain(SENTINEL);
  });

  it("warns when GROKBOT_AGENT_ID is missing, and that warning is not a failure", async () => {
    const report = await runDoctor(input({ agentIdFromEnv: false, agentId: "" }));

    const agent = check(report, "agent_id");
    expect(agent.status).toBe("warn");
    expect(agent.fix).toContain("--agent-did");
    expect(report.ok).toBe(true);
  });

  it("warns when the agent id is the shared default", async () => {
    const report = await runDoctor(input({
      agentId: "grokbot-agent",
      agentIdFromEnv: true,
      readState: async () => ({
        entries: {
          [enrollStateKey(BASE, SENTINEL, "grokbot-agent")]: {
            last_enroll_at: "2026-11-03T11:00:00.000Z",
            cli_version: VERSION,
          },
        },
      }),
    }));

    const agent = check(report, "agent_id");
    expect(agent.status).toBe("warn");
    expect(agent.fix).toContain("grokbot-agent");
    expect(report.ok).toBe(true);
  });

  it("warns when the enroll record is old and the key check did not refresh it", async () => {
    const fetchImpl: FetchLike = async (url) => {
      if (url.endsWith("/health")) {
        return { ok: true, status: 200, json: async () => ({}), text: async () => "" };
      }
      return { ok: false, status: 401, json: async () => ({}), text: async () => "" };
    };
    const report = await runDoctor(input({
      fetchImpl,
      readState: async () => ({
        entries: {
          [enrollStateKey(BASE, SENTINEL, AGENT)]: {
            last_enroll_at: "2026-11-01T12:00:00.000Z",
            cli_version: VERSION,
          },
        },
      }),
    }));

    const cache = check(report, "enroll_cache");
    expect(cache.status).toBe("warn");
    expect(cache.fix).toContain("enroll");
    expect(cache.fix?.toLowerCase()).toContain("limit");
    expect(rendered(report)).not.toContain(SENTINEL);
  });

  it("refreshes an old enroll record when the key check is accepted", async () => {
    let saved = "";
    const report = await runDoctor(input({
      readState: async () => ({ entries: {} }),
      recordEnroll: async (_key, version, at) => {
        saved = `${version} ${at.toISOString()}`;
      },
    }));

    expect(check(report, "enroll_cache").status).toBe("ok");
    expect(saved.startsWith(`${VERSION} `)).toBe(true);
    expect(report.ok).toBe(true);
  });

  it("treats a fresh enroll record as ok", async () => {
    const report = await runDoctor(input());

    expect(check(report, "enroll_cache").status).toBe("ok");
  });
});
