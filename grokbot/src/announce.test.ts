import { beforeEach, describe, expect, it } from "vitest";

import { announceInstance } from "./announce.js";
import { gateToolCall, resetAnnounceForTests, type SkillConfig } from "./gate.js";
import type { FetchLike } from "./client.js";

type Captured = { url: string; init: Parameters<FetchLike>[1] };

function fakeFetch(
  status = 200,
  decision: unknown = { outcome: "allow", decision_id: "d1", reasons: [] },
): { impl: FetchLike; calls: Captured[] } {
  const calls: Captured[] = [];
  const impl: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => decision,
      text: async () => JSON.stringify(decision),
    };
  };
  return { impl, calls };
}

const CFG: SkillConfig = {
  apiKey: "cnx_test",
  baseUrl: "https://engine.example",
  announce: true,
  instance: "ops-desk",
  announceAgents: ["bot-ops", "bot-hidden"],
  announceSkills: ["artzain"],
};

beforeEach(() => resetAnnounceForTests());

describe("announceInstance", () => {
  it("POSTs names-only identity with source grokbot", async () => {
    const { impl, calls } = fakeFetch();
    const out = await announceInstance(CFG, impl);
    expect(out.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://engine.example/api/v1/registry/announce");
    expect(calls[0].init.headers["X-Api-Key"]).toBe("cnx_test");
    expect(JSON.parse(calls[0].init.body as string)).toEqual({
      source: "grokbot",
      instance: "ops-desk",
      agents: ["bot-ops", "bot-hidden"],
      skills: ["artzain"],
    });
  });

  it("does nothing unless announce is exactly true", async () => {
    const { impl, calls } = fakeFetch();
    for (const announce of [undefined, false, "true", 1] as unknown[]) {
      const out = await announceInstance(
        { ...CFG, announce: announce as boolean | undefined },
        impl,
      );
      expect(out.ok).toBe(false);
    }
    expect(calls).toHaveLength(0);
  });

  it("skips without key or instance name, never throwing", async () => {
    const { impl, calls } = fakeFetch();
    expect((await announceInstance({ ...CFG, apiKey: "" }, impl)).ok).toBe(false);
    expect((await announceInstance({ ...CFG, instance: " " }, impl)).ok).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("falls back to agentDid then grokbot-agent", async () => {
    const { impl, calls } = fakeFetch();
    await announceInstance(
      { ...CFG, announceAgents: [], agentDid: "bot-7" },
      impl,
    );
    expect(JSON.parse(calls[0].init.body as string).agents).toEqual(["bot-7"]);
    calls.length = 0;
    await announceInstance({ ...CFG, announceAgents: [], agentDid: "" }, impl);
    expect(JSON.parse(calls[0].init.body as string).agents).toEqual(["grokbot-agent"]);
  });

  it("truncates on code points — never leaves a lone surrogate", async () => {
    const { impl, calls } = fakeFetch();
    const boundary = "a".repeat(199) + "😀suffix";
    await announceInstance(
      { ...CFG, announceAgents: [boundary], instance: "i".repeat(119) + "😀x" },
      impl,
    );
    const body = JSON.parse(calls[0].init.body as string);
    for (const name of [body.instance, ...body.agents]) {
      const last = name.charCodeAt(name.length - 1);
      expect(last >= 0xd800 && last <= 0xdbff).toBe(false);
    }
    expect(Array.from(body.agents[0] as string).length).toBe(200);
  });

  it("classifies transience: network/5xx/429 retryable, 4xx not", async () => {
    expect((await announceInstance(CFG, fakeFetch(503).impl)).retryable).toBe(true);
    expect((await announceInstance(CFG, fakeFetch(429).impl)).retryable).toBe(true);
    expect((await announceInstance(CFG, fakeFetch(422).impl)).retryable).toBe(false);
    const failing: FetchLike = async () => {
      throw new Error("network down");
    };
    expect((await announceInstance(CFG, failing)).retryable).toBe(true);
  });
});

describe("gateToolCall", () => {
  it("posts tool_call with surface grokbot and allows", async () => {
    const { impl, calls } = fakeFetch();
    const out = await gateToolCall(CFG, { toolName: "send_email", params: { to: "ops" } }, impl);
    expect(out.allow).toBe(true);
    const decisionCalls = calls.filter((c) => c.url.endsWith("/decisions"));
    expect(decisionCalls).toHaveLength(1);
    const sent = JSON.parse(decisionCalls[0].init.body as string);
    expect(sent.payload_kind).toBe("tool_call");
    expect(sent.surface).toBe("grokbot");
    expect(sent.action).toBe("send_email");
    expect(JSON.stringify(sent)).not.toContain("eyJ");
    expect(decisionCalls[0].url).not.toContain("envelope");
  });

  it("blocks deny, review, and missing key — failing closed", async () => {
    const deny = fakeFetch(200, { outcome: "deny", decision_id: "d2", reasons: ["no"] });
    const denied = await gateToolCall(CFG, { toolName: "exec" }, deny.impl);
    expect(denied.allow).toBe(false);
    expect(denied.blockReason).toContain("REFUSED");

    resetAnnounceForTests();
    const review = fakeFetch(200, { outcome: "review", decision_id: "d3", reasons: ["human"] });
    const queued = await gateToolCall(CFG, { toolName: "exec" }, review.impl);
    expect(queued.allow).toBe(false);
    expect(queued.blockReason).toContain("QUEUED FOR REVIEW");

    const missing = await gateToolCall({ ...CFG, apiKey: "" }, { toolName: "exec" }, fakeFetch().impl);
    expect(missing.allow).toBe(false);
    expect(missing.blockReason).toContain("failing closed");
  });

  it("HTTP 503 fails closed", async () => {
    const out = await gateToolCall(
      { ...CFG, announce: false },
      { toolName: "exec" },
      fakeFetch(503, { detail: "audit_unavailable" }).impl,
    );
    expect(out.allow).toBe(false);
    expect(out.blockReason).toContain("failing closed");
  });

  it("fires announce once and never blocks gating", async () => {
    const { impl, calls } = fakeFetch();
    const r1 = await gateToolCall(CFG, { toolName: "exec" }, impl);
    const r2 = await gateToolCall(CFG, { toolName: "exec" }, impl);
    expect(r1.allow).toBe(true);
    expect(r2.allow).toBe(true);
    const announceCalls = calls.filter((c) => c.url.endsWith("/registry/announce"));
    const decisionCalls = calls.filter((c) => c.url.endsWith("/decisions"));
    expect(announceCalls).toHaveLength(1);
    expect(decisionCalls).toHaveLength(2);
    expect(JSON.parse(announceCalls[0].init.body as string).source).toBe("grokbot");
  });

  it("a failing announce leaves the decision gate untouched", async () => {
    const impl: FetchLike = async (url, init) => {
      if (url.endsWith("/registry/announce")) {
        throw new Error("announce endpoint down");
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ outcome: "allow", decision_id: "d1", reasons: [] }),
        text: async () => "{}",
      };
    };
    const result = await gateToolCall(CFG, { toolName: "exec" }, impl);
    expect(result.allow).toBe(true);
  });
});
