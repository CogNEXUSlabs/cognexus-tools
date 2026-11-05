/**
 * Fixture logs for `coverage`: a shim line, a gateway line, and a journal
 * line. An action with a decision id is matched. One without is listed.
 * Two lines that share a decision id count once.
 */

import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  actionCounts,
  appendActionLine,
  readActionLog,
  runCoverage,
  unmatchedActions,
  type ActionRecord,
  type CoverageReport,
} from "./coverage.js";

const SINCE = "2026-11-04T08:00:00Z";
const START = new Date(SINCE);

const SHIM = [
  '{"at":"2026-11-04T07:00:00Z","agent":"ops-bot","action":"run_command","target":"shell:host/old.example","decision_id":""}',
  '{"at":"2026-11-04T16:00:00Z","agent":"ops-bot","action":"run_command","target":"shell:host/api.example","decision_id":"dec-shim"}',
  '{"at":"2026-11-04T16:05:00Z","agent":"ops-bot","action":"run_command","target":"shell:host/secret.example","decision_id":""}',
  "not json",
].join("\n");

const GATEWAY = [
  '{"at":"2026-11-04T16:10:00Z","agent":"notes-bot","action":"write_file","target":"file:path/notes.txt","decision_id":"dec-gw"}',
  '{"at":"2026-11-04T16:11:00Z","agent":"notes-bot","action":"write_file","target":"file:path/other.txt","decision_id":""}',
].join("\n");

const JOURNAL = [
  '{"at":"2026-11-04T16:20:00Z","agent":"ops-bot","action":"send_email","target":"mailbox","decision_id":"dec-mail"}',
  '{"at":"2026-11-04T16:21:00Z","agent":"ops-bot","action":"send_email","target":"mailbox","decision_id":"dec-shim"}',
  '{"at":"2026-11-04T16:22:00Z","agent":"","action":"send_email","target":"mailbox","decision_id":""}',
].join("\n");

function load(): ActionRecord[] {
  return [
    ...readActionLog(SHIM, "shim", START).actions,
    ...readActionLog(GATEWAY, "gateway", START).actions,
    ...readActionLog(JOURNAL, "journal", START).actions,
  ];
}

describe("fixture logs", () => {
  it("lists the actions that have no decision id and drops the one before --since", () => {
    const parsed = readActionLog(SHIM, "shim", START);
    expect(parsed.skipped).toBe(1);
    const unmatched = unmatchedActions(load());
    expect(unmatched.map((row) => `${row.source} ${row.target}`)).toEqual([
      "shim shell:host/secret.example",
      "gateway file:path/other.txt",
      "journal mailbox",
    ]);
    expect(JSON.stringify(unmatched)).not.toContain("cnx_");
    expect(JSON.stringify(unmatched)).not.toContain("dec-shim");
  });

  it("counts two lines that share a decision id once, and leaves a blank agent out of the report", () => {
    expect(actionCounts(load())).toEqual([
      { agent_id: "notes-bot", action_count: 2 },
      { agent_id: "ops-bot", action_count: 3 },
    ]);
  });
});

describe("runCoverage", () => {
  it("prints the unmatched lines and posts the counts", async () => {
    const dir = await mkdtemp(join(tmpdir(), "grokbot-coverage-"));
    await appendActionLine(join(dir, "shim.jsonl"), {
      at: "2026-11-04T16:05:00Z",
      agent: "ops-bot",
      action: "run_command",
      target: "shell:host/secret.example",
      decision_id: "",
    });
    await appendActionLine(join(dir, "gateway.jsonl"), {
      at: "2026-11-04T16:10:00Z",
      agent: "notes-bot",
      action: "write_file",
      target: "file:path/notes.txt",
      decision_id: "dec-gw",
    });
    const printed: string[] = [];
    const notes: string[] = [];
    let posted: CoverageReport | undefined;
    const code = await runCoverage({
      since: SINCE,
      logs: {
        shim: join(dir, "shim.jsonl"),
        gateway: join(dir, "gateway.jsonl"),
        journal: join(dir, "missing.jsonl"),
      },
      report: async (body) => {
        posted = body;
        return { ok: true, evaluated: true };
      },
      log: (line) => notes.push(line),
      print: (line) => printed.push(line),
    });

    expect(code).toBe(1);
    expect(printed).toEqual([
      JSON.stringify({
        at: "2026-11-04T16:05:00Z",
        source: "shim",
        agent: "ops-bot",
        action: "run_command",
        target: "shell:host/secret.example",
      }),
    ]);
    expect(posted).toEqual({
      since: SINCE,
      agents: [
        { agent_id: "notes-bot", action_count: 1 },
        { agent_id: "ops-bot", action_count: 1 },
      ],
    });
    expect(notes.join("\n")).toContain("1 action with no decision");
    const written = await readFile(join(dir, "shim.jsonl"), "utf8");
    expect(written).not.toContain("cnx_");
  });

  it("exits 2 when --since has no timezone, and sends nothing", async () => {
    let posted = false;
    const code = await runCoverage({
      since: "2026-11-04T08:00:00",
      logs: { shim: "unused", gateway: "unused", journal: "unused" },
      report: async () => {
        posted = true;
        return { ok: true, evaluated: false };
      },
      log: () => undefined,
      print: () => undefined,
    });
    expect(code).toBe(2);
    expect(posted).toBe(false);
  });
});
