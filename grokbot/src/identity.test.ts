/**
 * The agent id a decide sends is the id `announce` registered. A Bot that
 * passes its display name with a title, or some other name, asserts an id
 * its account never declared.
 */

import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { AgentVote, DecisionResponse } from "./client.js";
import {
  agentIdForDecide,
  announcedAgentIds,
  announcedIdUnderTitle,
  checkAgentId,
  declaredByService,
} from "./identity.js";
import {
  announceScope,
  announceStateKey,
  recordAnnounces,
  setStateDirectoryForTests,
  type EnrollState,
} from "./state.js";

const BASE = "https://engine.example";
const KEY = "cnx_test_identity_key";

function sandRoot(ids: string[]): string {
  const root = mkdtempSync(join(tmpdir(), "grokbot-identity-"));
  mkdirSync(join(root, "agents"), { recursive: true });
  for (const id of ids) mkdirSync(join(root, "agents", id));
  return root;
}

describe("an agent id given with a title", () => {
  it("is read as the announced id it starts with", () => {
    const announced = ["Mira", "Otto"];
    expect(announcedIdUnderTitle("Mira · Research lead", announced)).toBe("Mira");
    expect(announcedIdUnderTitle("Mira - Research lead", announced)).toBe("Mira");
    expect(announcedIdUnderTitle("Mira | Research lead", announced)).toBe("Mira");
    expect(announcedIdUnderTitle("Mira, Research lead", announced)).toBe("Mira");
    expect(announcedIdUnderTitle("Mira (Research lead)", announced)).toBe("Mira");
    expect(announcedIdUnderTitle("Mira: Research lead", announced)).toBe("Mira");
    expect(announcedIdUnderTitle("Mira — Research lead", announced)).toBe("Mira");
  });

  it("is not read as another id that only shares its first letters", () => {
    const announced = ["Mira", "Otto"];
    // Another name, another id: none of these is "Mira" with a title.
    expect(announcedIdUnderTitle("Mira B · Research lead", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mirabel · Research lead", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mira-2", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mira/eu", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mira:eu", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mira,eu", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mira|eu", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mira(2)", announced)).toBeUndefined();
    // A namespaced id is an id of its own, not "probe" with a title.
    expect(announcedIdUnderTitle("probe:latency", ["probe"])).toBeUndefined();
    expect(announcedIdUnderTitle("mira · Research lead", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Grok Bot", announced)).toBeUndefined();
    expect(announcedIdUnderTitle("Mira", announced)).toBeUndefined();
  });

  it("is left alone when two announced ids could be meant", () => {
    expect(announcedIdUnderTitle("Mira (EU) · Research lead", ["Mira", "Mira (EU)"])).toBeUndefined();
  });
});

describe("the agent id a decide sends", () => {
  it("is the given id when that id is announced, with nothing to say", () => {
    expect(checkAgentId("Mira", ["Mira", "Otto"])).toEqual({ agentDid: "Mira", replaced: false });
  });

  it("is the announced id when the given one adds a title, and the note names both", () => {
    const checked = checkAgentId("Mira · Research lead", ["Mira", "Otto"]);
    expect(checked.agentDid).toBe("Mira");
    expect(checked.replaced).toBe(true);
    expect(checked.note).toContain('"Mira · Research lead"');
    expect(checked.note).toContain('"Mira"');
  });

  it("is the given id when no announced id fits, and the note says the hosted service denies it", () => {
    const checked = checkAgentId("Grok Bot", ["Mira", "Otto"]);
    expect(checked.agentDid).toBe("Grok Bot");
    expect(checked.replaced).toBe(false);
    expect(checked.note).toContain('"Grok Bot"');
    expect(checked.note).toContain("not");
    expect(checked.note).toContain("hosted service denies");
    expect(checked.note).toContain("Mira, Otto");
  });

  it("says nothing when this host has announced nothing it can compare with", () => {
    expect(checkAgentId("Grok Bot", [])).toEqual({ agentDid: "Grok Bot", replaced: false });
  });

  it("names at most twelve announced ids, and never a control character", () => {
    const many = Array.from({ length: 30 }, (_, i) => `bot-${String(i).padStart(2, "0")}`);
    const checked = checkAgentId("line\nbreak\u001b[31m", many);
    expect(checked.note).toContain("bot-11");
    expect(checked.note).not.toContain("bot-12");
    expect(checked.note).toContain("18 more");
    expect(checked.note).not.toContain("\n");
    expect(checked.note).not.toContain("\u001b");
  });
});

describe("the ids this host announced", () => {
  it("are the host's profiles and the names announce recorded for this base URL and key", () => {
    const scope = announceScope(BASE, KEY);
    const state: EnrollState = {
      entries: {},
      announces: {
        [announceStateKey(BASE, KEY, "ops-desk", "named-bot")]: {
          last_announce_at: "2026-11-24T00:00:00.000Z",
          agent: "named-bot",
          scope,
        },
        [announceStateKey(BASE, "cnx_another_key", "ops-desk", "other-account-bot")]: {
          last_announce_at: "2026-11-24T00:00:00.000Z",
          agent: "other-account-bot",
          scope: announceScope(BASE, "cnx_another_key"),
        },
        // A record an older version wrote: a time, and no name.
        [announceStateKey(BASE, KEY, "ops-desk", "old-bot")]: {
          last_announce_at: "2026-11-01T00:00:00.000Z",
        },
      },
    };
    const ids = announcedAgentIds({ sandRoot: sandRoot(["Otto", "Mira"]), state, baseUrl: BASE, apiKey: KEY });
    expect(ids).toEqual(["Mira", "Otto", "named-bot"]);
  });

  it("are empty on a host with no profiles and no record", () => {
    const empty = mkdtempSync(join(tmpdir(), "grokbot-identity-empty-"));
    expect(announcedAgentIds({ sandRoot: empty, state: null, baseUrl: BASE, apiKey: KEY })).toEqual([]);
  });
});

describe("a decide's agent id, read against this host", () => {
  beforeEach(() => {
    setStateDirectoryForTests(mkdtempSync(join(tmpdir(), "grokbot-identity-state-")));
  });
  afterEach(() => {
    setStateDirectoryForTests(undefined);
  });

  it("is the announced id for a titled one, from the profiles alone", async () => {
    const env = { SAND_DATA_ROOT: sandRoot(["Mira", "Otto"]) };
    const checked = await agentIdForDecide({ given: "Mira · Research lead", env, apiKey: KEY, baseUrl: BASE });
    expect(checked.agentDid).toBe("Mira");
    expect(checked.replaced).toBe(true);
    // No key: the profiles are still read.
    expect((await agentIdForDecide({ given: "Otto | Ops", env, baseUrl: BASE })).agentDid).toBe("Otto");
  });

  it("takes an id an older version announced, when the instance it used is known", async () => {
    // What 0.1.11 and earlier wrote: the time under a hash, and no name.
    await recordAnnounces([announceStateKey(BASE, KEY, "ops-desk", "old-bot")], new Date("2026-11-01T00:00:00.000Z"));
    const env = { SAND_DATA_ROOT: sandRoot(["Mira"]) };

    const known = await agentIdForDecide({ given: "old-bot", env, apiKey: KEY, baseUrl: BASE, instance: "ops-desk" });
    expect(known).toEqual({ agentDid: "old-bot", replaced: false });

    const unknown = await agentIdForDecide({ given: "old-bot", env, apiKey: KEY, baseUrl: BASE });
    expect(unknown.agentDid).toBe("old-bot");
    expect(unknown.note).toContain("grokbot-artzain announce");
  });

  it("does not replace a titled id that was itself announced", async () => {
    const titled = "Mira · Research lead";
    await recordAnnounces(
      [announceStateKey(BASE, KEY, "ops-desk", titled)],
      new Date("2026-11-24T00:00:00.000Z"),
      { scope: announceScope(BASE, KEY), agents: [titled] },
    );
    const env = { SAND_DATA_ROOT: sandRoot(["Mira"]) };
    expect(await agentIdForDecide({ given: titled, env, apiKey: KEY, baseUrl: BASE })).toEqual({
      agentDid: titled,
      replaced: false,
    });
  });
});

describe("an allow that says the service knows the agent id", () => {
  function vote(over: Partial<AgentVote>): AgentVote {
    return {
      name: "agent-registry",
      verdict: "allow",
      severity: "none",
      score: null,
      findings: [],
      error: null,
      ...over,
    };
  }

  function answer(votes: AgentVote[], outcome: DecisionResponse["outcome"] = "allow"): DecisionResponse {
    return {
      outcome,
      decision_id: "d1",
      audit_block_id: "b1",
      contributing_agents: votes,
      policy_bundle_version: "v1",
      resolution_policy: "strictest",
      latency_ms: 1,
      reasons: [],
    };
  }

  it("is the registry's allow with no finding", () => {
    expect(declaredByService(answer([vote({ name: "tool-call-contract" }), vote({})]))).toBe(true);
  });

  it("is not an allow that names the id as not in the registry", () => {
    expect(declaredByService(answer([vote({ severity: "low", findings: ["agent 'Grok Bot' not in registry"] })])))
      .toBe(false);
  });

  it("is not an answer without the registry's vote, or with a vote that failed or did not allow", () => {
    expect(declaredByService(answer([vote({ name: "tool-call-contract" })]))).toBe(false);
    expect(declaredByService(answer([]))).toBe(false);
    expect(declaredByService({ ...answer([]), contributing_agents: undefined } as unknown as DecisionResponse))
      .toBe(false);
    expect(declaredByService(answer([vote({ error: "registry_unavailable" })]))).toBe(false);
    expect(declaredByService(answer([vote({ verdict: "review", severity: "high" })]))).toBe(false);
    expect(declaredByService(answer([vote({})], "review"))).toBe(false);
  });
});
