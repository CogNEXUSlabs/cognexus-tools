/**
 * A decide is asked again only when the engine can replay it. The same
 * request id goes on every attempt, and the attempts share one deadline.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeEach, describe, expect, it } from "vitest";

import { DecisionError, postDecision, type FetchLike } from "./client.js";
import { gateToolCall, resetEnrollForTests, type SkillConfig } from "./gate.js";
import { setStateDirectoryForTests } from "./state.js";

const ALLOW = {
  outcome: "allow",
  decision_id: "d1",
  audit_block_id: "b1",
  contributing_agents: [],
  policy_bundle_version: "builtin:v0",
  resolution_policy: "builtin/strict-v0",
  latency_ms: 1,
  reasons: [],
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

interface Sent {
  requestId: string | null;
}

function scripted(
  steps: Array<{ status: number; detail?: unknown; retryAfter?: string }>,
): { impl: FetchLike; sent: Sent[] } {
  const sent: Sent[] = [];
  let n = 0;
  const impl: FetchLike = async (_url, init) => {
    const body = JSON.parse(init.body ?? "{}") as { request_id?: string | null };
    sent.push({ requestId: body.request_id ?? null });
    const step = steps[Math.min(n, steps.length - 1)];
    n += 1;
    const ok = step.status >= 200 && step.status < 300;
    const payload = ok ? ALLOW : { detail: step.detail };
    return {
      ok,
      status: step.status,
      headers: {
        get(name: string) {
          return name.toLowerCase() === "retry-after" ? (step.retryAfter ?? null) : null;
        },
      },
      json: async () => payload,
      text: async () => JSON.stringify(payload),
    } as Awaited<ReturnType<FetchLike>>;
  };
  return { impl, sent };
}

const base = {
  apiKey: "cnx_test",
  baseUrl: "https://engine.example",
  action: "exec",
  target: "grokbot:tool:exec",
  payload: "{}",
  agentDid: "bot",
};

function ids(sent: Sent[]): Array<string | null> {
  return sent.map((row) => row.requestId);
}

describe("decide retries", () => {
  it("generates one request id, and --request-id replaces it", async () => {
    const generated = scripted([{ status: 200 }]);
    await postDecision({ ...base, fetchImpl: generated.impl });
    expect(generated.sent).toHaveLength(1);
    expect(generated.sent[0].requestId).toMatch(UUID);

    const chosen = scripted([{ status: 200 }]);
    await postDecision({ ...base, requestId: "order-8812", fetchImpl: chosen.impl });
    expect(chosen.sent[0].requestId).toBe("order-8812");
  });

  it.each([
    ["401", 401, "unauthorized"],
    ["403", 403, "forbidden"],
    ["404", 404, "missing"],
    ["422", 422, "invalid"],
    ["302", 302, undefined],
    ["503 kill_switch_active", 503, "kill_switch_active"],
    ["503 with another detail", 503, "something_else"],
    ["500", 500, "error"],
  ] as const)("does not retry HTTP %s", async (_name, status, detail) => {
    const { impl, sent } = scripted([{ status, detail }]);
    const err = await postDecision({ ...base, fetchImpl: impl }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect(sent).toHaveLength(1);
  });

  it.each([
    ["503 audit_unavailable", 503, "audit_unavailable"],
    ["503 cited_review_unavailable", 503, "cited_review_unavailable"],
    ["429", 429, "throughput_exceeded"],
  ] as const)("retries HTTP %s three times with one request id", async (_name, status, detail) => {
    const { impl, sent } = scripted([{ status, detail, retryAfter: "0" }]);
    const err = await postDecision({ ...base, fetchImpl: impl }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect((err as DecisionError).status).toBe(status);
    expect(sent).toHaveLength(3);
    expect(new Set(ids(sent)).size).toBe(1);
    expect(sent[0].requestId).toMatch(UUID);
  });

  it("retries a network error three times with one request id", async () => {
    const sent: Sent[] = [];
    const impl: FetchLike = async (_url, init) => {
      const body = JSON.parse(init.body ?? "{}") as { request_id?: string | null };
      sent.push({ requestId: body.request_id ?? null });
      throw Object.assign(new Error("connect failed"), { code: "ECONNREFUSED" });
    };
    const err = await postDecision({ ...base, fetchImpl: impl }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DecisionError);
    expect((err as DecisionError).message).toContain("ECONNREFUSED");
    expect(sent).toHaveLength(3);
    expect(new Set(ids(sent)).size).toBe(1);
  });

  it("returns the decision from a later attempt and keeps the id", async () => {
    const { impl, sent } = scripted([
      { status: 503, detail: "audit_unavailable" },
      { status: 200 },
    ]);
    const result = await postDecision({ ...base, requestId: "order-8812", fetchImpl: impl });
    expect(result.outcome).toBe("allow");
    expect(ids(sent)).toEqual(["order-8812", "order-8812"]);
  });

  it("does not wait past the decide deadline for Retry-After", async () => {
    const { impl, sent } = scripted([{ status: 429, detail: "throughput_exceeded", retryAfter: "30" }]);
    const started = Date.now();
    const err = await postDecision({ ...base, timeoutMs: 80, fetchImpl: impl }).catch((e: unknown) => e);
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(err).toBeInstanceOf(DecisionError);
    expect((err as DecisionError).status).toBe(429);
    expect(sent).toHaveLength(1);
  });

  it("does not retry a timeout, and stops inside the deadline", async () => {
    let calls = 0;
    const impl: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        calls += 1;
        init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const started = Date.now();
    const err = await postDecision({ ...base, timeoutMs: 50, fetchImpl: impl }).catch((e: unknown) => e);
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(calls).toBe(1);
    expect(err).toBeInstanceOf(DecisionError);
    expect((err as DecisionError).message).toContain("TimeoutError");
  });

  it("waits out a Retry-After that fits, then uses the same id", async () => {
    const { impl, sent } = scripted([
      { status: 429, detail: "throughput_exceeded", retryAfter: "0.05" },
      { status: 200 },
    ]);
    const started = Date.now();
    const result = await postDecision({ ...base, requestId: "order-8812", fetchImpl: impl });
    expect(Date.now() - started).toBeGreaterThanOrEqual(40);
    expect(result.outcome).toBe("allow");
    expect(ids(sent)).toEqual(["order-8812", "order-8812"]);
  });
});

describe("an exhausted decide", () => {
  beforeEach(() => {
    resetEnrollForTests();
    setStateDirectoryForTests(mkdtempSync(join(tmpdir(), "grokbot-retry-")));
  });

  it("still fails closed", async () => {
    const { impl, sent } = scripted([{ status: 503, detail: "audit_unavailable", retryAfter: "0" }]);
    const cfg: SkillConfig = {
      apiKey: "cnx_test",
      baseUrl: "https://engine.example",
      enroll: false,
      announce: false,
    };
    const result = await gateToolCall(cfg, { toolName: "exec" }, impl);
    expect(result.allow).toBe(false);
    if (result.allow) return;
    expect(result.blockReason).toContain("failing closed");
    expect(sent).toHaveLength(3);
    expect(new Set(ids(sent)).size).toBe(1);
  });
});
