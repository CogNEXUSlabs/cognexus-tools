import { beforeEach, describe, expect, it } from "vitest";

import { announceInstance } from "./announce.js";
import {
  handleBeforeToolCall,
  resetAnnounceForTests,
  type PluginConfig,
} from "./gate.js";
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
    };
  };
  return { impl, calls };
}

const CFG: PluginConfig = {
  apiKey: "cnx_test",
  baseUrl: "https://engine.example",
  announce: true,
  instance: "jeans-laptop",
  announceAgents: ["main", "researcher"],
  announceSkills: ["artzain"],
};

beforeEach(() => resetAnnounceForTests());

describe("announceInstance", () => {
  it("POSTs names-only identity with the decision key", async () => {
    const { impl, calls } = fakeFetch();
    const out = await announceInstance(CFG, impl);
    expect(out.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://engine.example/api/v1/registry/announce");
    expect(calls[0].init.headers["X-Api-Key"]).toBe("cnx_test");
    expect(JSON.parse(calls[0].init.body)).toEqual({
      instance: "jeans-laptop",
      agents: ["main", "researcher"],
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

  it("falls back to agentDid when no agents are configured", async () => {
    const { impl, calls } = fakeFetch();
    await announceInstance(
      { ...CFG, announceAgents: [], agentDid: "gw-7" },
      impl,
    );
    expect(JSON.parse(calls[0].init.body).agents).toEqual(["gw-7"]);
  });

  it("truncates on code points — never leaves a lone surrogate", async () => {
    // An emoji straddling the 200-unit boundary under String.slice would
    // leave a lone high surrogate the server rightly 422-refuses — which
    // (as a 4xx) would latch announce off for the process.
    const { impl, calls } = fakeFetch();
    const boundary = "a".repeat(199) + "😀suffix";
    await announceInstance(
      { ...CFG, announceAgents: [boundary], instance: "i".repeat(119) + "😀x" },
      impl,
    );
    const body = JSON.parse(calls[0].init.body);
    for (const name of [body.instance, ...body.agents]) {
      const last = name.charCodeAt(name.length - 1);
      expect(last >= 0xd800 && last <= 0xdbff).toBe(false);
    }
    expect(Array.from(body.agents[0]).length).toBe(200);
  });

  it("dedupes, trims, and drops non-string names", async () => {
    const { impl, calls } = fakeFetch();
    await announceInstance(
      {
        ...CFG,
        announceAgents: [" main ", "main", 7 as unknown as string, ""],
        announceSkills: ["s ", "s"],
      },
      impl,
    );
    const body = JSON.parse(calls[0].init.body);
    expect(body.agents).toEqual(["main"]);
    expect(body.skills).toEqual(["s"]);
  });

  it("reports refusal statuses without throwing", async () => {
    const { impl } = fakeFetch(429);
    const out = await announceInstance(CFG, impl);
    expect(out.ok).toBe(false);
    expect(out.status).toBe(429);
  });

  it("classifies transience: network/5xx/429 retryable, 4xx not", async () => {
    expect((await announceInstance(CFG, fakeFetch(503).impl)).retryable).toBe(true);
    expect((await announceInstance(CFG, fakeFetch(429).impl)).retryable).toBe(true);
    expect((await announceInstance(CFG, fakeFetch(422).impl)).retryable).toBe(false);
    expect((await announceInstance(CFG, fakeFetch(401).impl)).retryable).toBe(false);
    const failing: FetchLike = async () => {
      throw new Error("network down");
    };
    expect((await announceInstance(CFG, failing)).retryable).toBe(true);
  });

  it("non-string scalar config resolves as a logged skip, never a throw", async () => {
    const { impl, calls } = fakeFetch();
    const logs: string[] = [];
    const out = await announceInstance(
      { ...CFG, instance: 42 as unknown as string },
      impl,
      (m) => logs.push(m),
    );
    expect(out.ok).toBe(false);
    expect(calls).toHaveLength(0);
    expect(logs.some((l) => l.includes("instance"))).toBe(true);
  });

  it("prefers the hook context agentId for the default identity", async () => {
    const { impl, calls } = fakeFetch();
    await announceInstance(
      { ...CFG, announceAgents: [], agentDid: "cfg-did" },
      impl,
      () => {},
      "ctx-agent",
    );
    expect(JSON.parse(calls[0].init.body).agents).toEqual(["ctx-agent"]);
  });

  it("surfaces the server's deferred count in the success log", async () => {
    const { impl } = fakeFetch(200, {
      instance: "jeans-laptop", agents_announced: 1, skills_recorded: 0,
      registered: 0, seen: 0, blocked: 0, deferred: 1,
    });
    const logs: string[] = [];
    const out = await announceInstance(CFG, impl, (m) => logs.push(m));
    expect(out.ok).toBe(true);
    expect(logs.join("\n")).toContain("deferred 1");
    expect(logs.join("\n")).toContain("not retried until a re-announce");
  });

  it("surfaces the server's failed count in the success log", async () => {
    // An announce the server accepted but could not persist: HTTP 200 with
    // registered 0. Dropping `failed` here would report "registered 0, seen
    // 0, blocked 0, deferred 0" — a clean-looking line for an announce that
    // catalogued nothing.
    const { impl } = fakeFetch(200, {
      instance: "jeans-laptop", agents_announced: 2, skills_recorded: 0,
      registered: 0, seen: 0, blocked: 0, deferred: 0, failed: 2,
    });
    const logs: string[] = [];
    const out = await announceInstance(CFG, impl, (m) => logs.push(m));
    expect(out.ok).toBe(true);
    expect(logs.join("\n")).toContain("failed 2");
    expect(logs.join("\n")).toContain("were NOT stored");
  });

  it("reports failed 0 on a server that does not send the count", async () => {
    const { impl } = fakeFetch(200, {
      instance: "jeans-laptop", agents_announced: 1, skills_recorded: 0,
      registered: 1, seen: 0, blocked: 0, deferred: 0,
    });
    const logs: string[] = [];
    await announceInstance(CFG, impl, (m) => logs.push(m));
    expect(logs.join("\n")).toContain("failed 0");
    expect(logs.join("\n")).not.toContain("were NOT stored");
  });
});

describe("gate integration", () => {
  const EVENT = { toolName: "exec", toolCallId: "t1" };

  it("fires announce once and never blocks gating", async () => {
    const { impl, calls } = fakeFetch();
    const ctx = { pluginConfig: CFG };
    const r1 = await handleBeforeToolCall(EVENT, ctx, impl);
    const r2 = await handleBeforeToolCall(EVENT, ctx, impl);
    expect(r1).toBeUndefined(); // allow
    expect(r2).toBeUndefined();
    const announceCalls = calls.filter((c) => c.url.endsWith("/registry/announce"));
    const decisionCalls = calls.filter((c) => c.url.endsWith("/decisions"));
    expect(announceCalls).toHaveLength(1); // once per process
    expect(decisionCalls).toHaveLength(2);
  });

  it("gates normally when announce is off — no announce traffic", async () => {
    const { impl, calls } = fakeFetch();
    await handleBeforeToolCall(EVENT, { pluginConfig: { apiKey: "cnx_test" } }, impl);
    expect(calls.filter((c) => c.url.endsWith("/registry/announce"))).toHaveLength(0);
  });

  it("a failing announce endpoint leaves the decision gate untouched", async () => {
    const calls: Captured[] = [];
    const impl: FetchLike = async (url, init) => {
      calls.push({ url, init });
      if (url.endsWith("/registry/announce")) {
        throw new Error("announce endpoint down");
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ outcome: "allow", decision_id: "d1", reasons: [] }),
      };
    };
    const result = await handleBeforeToolCall(EVENT, { pluginConfig: CFG }, impl);
    expect(result).toBeUndefined(); // gate allowed despite announce failure
  });

  it("retries announce on a later call after a transient failure only", async () => {
    let announceAttempts = 0;
    let failFirst = true;
    const impl: FetchLike = async (url, init) => {
      if (url.endsWith("/registry/announce")) {
        announceAttempts += 1;
        if (failFirst) {
          failFirst = false;
          throw new Error("offline");
        }
        return { ok: true, status: 200, json: async () => ({ registered: 1 }) };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ outcome: "allow", decision_id: "d1", reasons: [] }),
      };
    };
    const ctx = { pluginConfig: CFG };
    await handleBeforeToolCall(EVENT, ctx, impl);
    await new Promise((r) => setTimeout(r, 0)); // let the floating promise settle
    await handleBeforeToolCall(EVENT, ctx, impl); // retries after network failure
    await new Promise((r) => setTimeout(r, 0));
    await handleBeforeToolCall(EVENT, ctx, impl); // succeeded — no third attempt
    await new Promise((r) => setTimeout(r, 0));
    expect(announceAttempts).toBe(2);
  });

  it("does not retry after a 4xx config refusal", async () => {
    let announceAttempts = 0;
    const impl: FetchLike = async (url, init) => {
      if (url.endsWith("/registry/announce")) {
        announceAttempts += 1;
        return { ok: false, status: 422, json: async () => ({ detail: "bad" }) };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ outcome: "allow", decision_id: "d1", reasons: [] }),
      };
    };
    const ctx = { pluginConfig: CFG };
    await handleBeforeToolCall(EVENT, ctx, impl);
    await new Promise((r) => setTimeout(r, 0));
    await handleBeforeToolCall(EVENT, ctx, impl);
    await new Promise((r) => setTimeout(r, 0));
    expect(announceAttempts).toBe(1);
  });
});
