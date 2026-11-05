/**
 * A stored decide stays fail-closed. Retry sends the original request id.
 * An entry older than 48 hours is dropped, with a note.
 */

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { FetchLike } from "./client.js";
import { enqueueDecision, expiredNote, listQueue, queueDirectory, retryQueue, type QueuedRequest } from "./queue.js";
import { setStateDirectoryForTests } from "./state.js";

const HOUR_MS = 60 * 60 * 1000;
const WINDOW_MS = 48 * HOUR_MS;

const LIVE: Omit<QueuedRequest, "queued_at"> = {
  base_url: "https://engine.example",
  agent_did: "research-bot",
  action: "send_email",
  target: "mailbox",
  payload: JSON.stringify({
    tool: "send_email",
    arguments: { to: "ops@example.com", body: "the full request, which a hash would drop" },
  }),
  request_id: "order-8812",
  product: "grokbot-artzain@0.1.10",
};

beforeEach(() => {
  setStateDirectoryForTests(mkdtempSync(join(tmpdir(), "grokbot-queue-")));
});

afterEach(() => {
  setStateDirectoryForTests(undefined);
});

function files(): string[] {
  return readdirSync(queueDirectory()).filter((name) => name.endsWith(".json"));
}

describe("the decision queue", () => {
  it("retries with the original request id, and a replay does not allow the action", async () => {
    const at = new Date("2026-11-01T00:00:00.000Z");
    await enqueueDecision({ ...LIVE, request_id: "order-old" }, at);
    await enqueueDecision(LIVE, new Date(at.getTime() + WINDOW_MS));
    if (process.platform !== "win32") {
      expect(statSync(join(queueDirectory(), files()[0]!)).mode & 0o777).toBe(0o600);
    }

    const kept = await listQueue(at.getTime() + WINDOW_MS);
    expect(kept.notes).toEqual([]);
    expect(kept.entries.map((entry) => entry.request_id).sort()).toEqual(["order-8812", "order-old"]);

    const livePath = join(
      queueDirectory(),
      files().find((name) => readFileSync(join(queueDirectory(), name), "utf8").includes("order-8812"))!,
    );
    const onDisk = JSON.parse(readFileSync(livePath, "utf8")) as QueuedRequest & { api_key?: string };
    onDisk.api_key = "cnx_from_disk";
    writeFileSync(livePath, JSON.stringify(onDisk));

    const sent: Array<{ body: Record<string, unknown>; apiKey: string }> = [];
    const fetchImpl: FetchLike = async (_url, init) => {
      sent.push({
        body: JSON.parse(init.body ?? "{}") as Record<string, unknown>,
        apiKey: init.headers["X-Api-Key"] ?? "",
      });
      const body = {
        outcome: "allow",
        decision_id: "d1",
        reasons: [],
        audit_block_id: "a",
        contributing_agents: [],
        policy_bundle_version: "0",
        resolution_policy: "default",
        latency_ms: 1,
      };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    };

    const report = await retryQueue({
      apiKey: "cnx_live_key",
      fetchImpl,
      now: at.getTime() + WINDOW_MS + 1,
    });

    expect(report.acted).toBe(false);
    expect(report.records).toEqual([
      { request_id: "order-8812", recorded: "allow", decision_id: "d1", acted: false },
    ]);
    expect(report.notes).toEqual([expiredNote("order-old")]);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body.request_id).toBe("order-8812");
    expect(sent[0]?.body.payload).toBe(LIVE.payload);
    expect(sent[0]?.body.product).toBe(LIVE.product);
    expect(sent[0]?.apiKey).toBe("cnx_live_key");
    expect(JSON.stringify(sent[0]?.body)).not.toContain("cnx_from_disk");
    expect(JSON.stringify(sent[0]?.body)).not.toContain("cnx_live_key");
    expect(files().some((name) => readFileSync(join(queueDirectory(), name), "utf8").includes("order-8812"))).toBe(false);
  });

  it("replays model, workload and context, and a recorded allow does not act", async () => {
    await enqueueDecision({
      ...LIVE,
      request_id: "order-ctx",
      model_id: "model-a",
      workload_id: "inbox",
      context: { session: "sess-1", parent: "01PARENT", on_behalf_of: "alice", trace: "keep-me" },
    });
    const sent: Array<Record<string, unknown>> = [];
    const fetchImpl: FetchLike = async (_url, init) => {
      sent.push(JSON.parse(init.body ?? "{}") as Record<string, unknown>);
      const body = {
        outcome: "allow",
        decision_id: "d9",
        reasons: [],
        audit_block_id: "a",
        contributing_agents: [],
        policy_bundle_version: "0",
        resolution_policy: "default",
        latency_ms: 1,
      };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    };

    const report = await retryQueue({ apiKey: "cnx_live_key", fetchImpl });

    expect(report.acted).toBe(false);
    expect(report.records).toEqual([
      { request_id: "order-ctx", recorded: "allow", decision_id: "d9", acted: false },
    ]);
    expect(sent[0]?.request_id).toBe("order-ctx");
    expect(sent[0]?.payload).toBe(LIVE.payload);
    expect(sent[0]?.model_id).toBe("model-a");
    expect(sent[0]?.workload_id).toBe("inbox");
    expect(sent[0]?.context).toEqual({
      session: "sess-1",
      parent: "01PARENT",
      on_behalf_of: "alice",
      trace: "keep-me",
    });
  });

  it("drops an entry older than 48 hours with a note, and keeps one at 48 hours", async () => {
    const at = new Date("2026-11-01T00:00:00.000Z");
    await enqueueDecision({ ...LIVE, request_id: "order-old" }, at);

    const still = await listQueue(at.getTime() + WINDOW_MS);
    expect(still.notes).toEqual([]);
    expect(still.entries.map((entry) => entry.request_id)).toEqual(["order-old"]);

    const dropped = await listQueue(at.getTime() + WINDOW_MS + 1);
    expect(dropped.entries).toEqual([]);
    expect(dropped.notes).toEqual([expiredNote("order-old")]);
    expect(dropped.notes[0]).toContain("dropped");
    expect(dropped.notes[0]).toContain("48");
  });
});
