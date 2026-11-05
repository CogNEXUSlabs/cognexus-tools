import { mkdtempSync, statSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { FetchLike } from "./client.js";
import {
  gateToolCall,
  resetEnrollForTests,
  settleEnrollForTests,
  type SkillConfig,
} from "./gate.js";
import {
  ANNOUNCE_TTL_MS,
  announceIsFresh,
  announceStateKey,
  currentCliVersion,
  enrollStateKey,
  readEnrollState,
  recordAnnounces,
  recordEnroll,
  replaceFile,
  setReplaceForTests,
  setStateDirectoryForTests,
  stateFilePath,
} from "./state.js";

const KEY = "cnx_test_state_key";
const CFG: SkillConfig = {
  apiKey: KEY,
  baseUrl: "https://engine.example",
  agentDid: "research-bot",
  announce: false,
};

function slot(): string {
  return enrollStateKey("https://engine.example", KEY, "research-bot");
}

function allow(): FetchLike {
  return async (url) => {
    const enroll = url.endsWith("/registry/enroll");
    const body = enroll
      ? { ok: true, adapter: { primary: "tool_gate" }, envelope: null }
      : { outcome: "allow", decision_id: "d1", reasons: [] };
    return {
      ok: true,
      status: 200,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  };
}

let dir: string;
let enrolls: number;

function countingAllow(): FetchLike {
  return async (url, init) => {
    if (url.endsWith("/registry/enroll")) enrolls += 1;
    return allow()(url, init);
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "grokbot-state-"));
  setStateDirectoryForTests(dir);
  resetEnrollForTests();
  setReplaceForTests(undefined);
  enrolls = 0;
});

afterEach(() => {
  setStateDirectoryForTests(undefined);
  setReplaceForTests(undefined);
  delete process.env.GROKBOT_ENROLL_TTL_HOURS;
});

async function saved() {
  return readEnrollState();
}

describe("enroll state", () => {
  it("enrolls on the first run and writes the record", async () => {
    await gateToolCall(CFG, { toolName: "exec" }, countingAllow());
    await settleEnrollForTests();

    expect(enrolls).toBe(1);
    const state = await saved();
    const row = state?.entries[slot()];
    expect(row?.cli_version).toBe(currentCliVersion());
    expect(row?.last_enroll_at).toBeTruthy();
    const text = await readFile(stateFilePath(), "utf8");
    expect(text).not.toContain(KEY);
    if (process.platform !== "win32") {
      expect(statSync(stateFilePath()).mode & 0o777).toBe(0o600);
    }
  });

  it("skips enroll when the record is fresh", async () => {
    await recordEnroll(slot(), currentCliVersion(), new Date());
    await gateToolCall(CFG, { toolName: "exec" }, countingAllow());
    await settleEnrollForTests();
    expect(enrolls).toBe(0);
  });

  it("enrolls again when the CLI version in the record is not this one", async () => {
    await recordEnroll(slot(), "0.0.1", new Date());
    await gateToolCall(CFG, { toolName: "exec" }, countingAllow());
    await settleEnrollForTests();
    expect(enrolls).toBe(1);
    expect((await saved())?.entries[slot()]?.cli_version).toBe(currentCliVersion());
  });

  it("enrolls again when the record is older than the TTL", async () => {
    process.env.GROKBOT_ENROLL_TTL_HOURS = "1";
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await recordEnroll(slot(), currentCliVersion(), old);
    await gateToolCall(CFG, { toolName: "exec", agentDid: "research-bot" }, countingAllow());
    await settleEnrollForTests();
    expect(enrolls).toBe(1);
  });

  it("treats corrupt JSON as a reason to enroll and rewrite", async () => {
    await mkdir(dir, { recursive: true });
    await writeFile(stateFilePath(), "{ not json", "utf8");
    await gateToolCall(CFG, { toolName: "exec" }, countingAllow());
    await settleEnrollForTests();
    expect(enrolls).toBe(1);
    const state = await saved();
    expect(state?.entries[slot()]?.cli_version).toBe(currentCliVersion());
  });

  it("keeps both entries when two writers save at once", async () => {
    const a = enrollStateKey("https://engine.example", KEY, "bot-a");
    const b = enrollStateKey("https://engine.example", KEY, "bot-b");
    await Promise.all([
      recordEnroll(a, "0.1.10", new Date("2026-11-01T00:00:00.000Z")),
      recordEnroll(b, "0.1.10", new Date("2026-11-02T00:00:00.000Z")),
    ]);
    const state = await saved();
    expect(state?.entries[a]?.last_enroll_at).toBe("2026-11-01T00:00:00.000Z");
    expect(state?.entries[b]?.last_enroll_at).toBe("2026-11-02T00:00:00.000Z");
  });

  it("retries a rename Windows refuses, and does not retry any other error", async () => {
    const from = join(dir, "new.json");
    const to = join(dir, "state.json");
    await writeFile(from, "{}\n", "utf8");
    let calls = 0;
    setReplaceForTests(async (src, dest) => {
      calls += 1;
      if (calls < 3) {
        const err = new Error("busy") as NodeJS.ErrnoException;
        err.code = "EPERM";
        throw err;
      }
      await rename(src, dest);
    }, 1_000);
    await replaceFile(from, to);
    expect(calls).toBe(3);
    expect(await readFile(to, "utf8")).toBe("{}\n");

    const other = join(dir, "other.json");
    await writeFile(other, "{}\n", "utf8");
    calls = 0;
    setReplaceForTests(async () => {
      calls += 1;
      const err = new Error("no") as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    }, 1_000);
    await expect(replaceFile(other, join(dir, "missing.json"))).rejects.toThrow("no");
    expect(calls).toBe(1);
  });

  it("keeps an announce record when it records an enroll, and the reverse", async () => {
    const announceKey = announceStateKey("https://engine.example", KEY, "ops-desk", "research-bot");
    await recordAnnounces([announceKey], new Date("2026-11-03T00:00:00.000Z"));
    await recordEnroll(slot(), currentCliVersion(), new Date("2026-11-04T00:00:00.000Z"));
    const state = await saved();
    expect(state?.announces[announceKey]?.last_announce_at).toBe("2026-11-03T00:00:00.000Z");
    expect(state?.entries[slot()]?.last_enroll_at).toBe("2026-11-04T00:00:00.000Z");
    await recordAnnounces([announceKey], new Date("2026-11-05T00:00:00.000Z"));
    const again = await saved();
    expect(again?.entries[slot()]?.cli_version).toBe(currentCliVersion());
    expect(again?.announces[announceKey]?.last_announce_at).toBe("2026-11-05T00:00:00.000Z");
  });

  it("does not enroll, and does not write, when enroll is exactly false", async () => {
    await gateToolCall({ ...CFG, enroll: false }, { toolName: "exec" }, countingAllow());
    await settleEnrollForTests();
    expect(enrolls).toBe(0);
    await expect(readFile(stateFilePath(), "utf8")).rejects.toThrow();
  });
});

describe("announce skip window", () => {
  it("is fresh until the window is exactly 24 hours", () => {
    const at = "2026-11-03T00:00:00.000Z";
    const start = Date.parse(at);
    expect(announceIsFresh({ last_announce_at: at }, start + ANNOUNCE_TTL_MS - 1)).toBe(true);
    expect(announceIsFresh({ last_announce_at: at }, start + ANNOUNCE_TTL_MS)).toBe(false);
    expect(announceIsFresh(undefined, start)).toBe(false);
  });
});
