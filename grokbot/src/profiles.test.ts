import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  isValidSandAgentId,
  listProfileAgentIds,
  readActiveProfileAgent,
  selectAnnounceAgents,
} from "./profiles.js";

function rootWith(ids: string[], active?: string): string {
  const root = mkdtempSync(join(tmpdir(), "grokbot-profiles-"));
  const agents = join(root, "agents");
  mkdirSync(agents, { recursive: true });
  for (const id of ids) mkdirSync(join(agents, id));
  if (active) {
    writeFileSync(join(agents, "active-agent.json"), JSON.stringify({ activeAgentId: active }), "utf8");
  }
  return root;
}

describe("profile agents", () => {
  it("refuses a folder name that could leave the agents directory", () => {
    expect(isValidSandAgentId("research-bot")).toBe(true);
    expect(isValidSandAgentId("../x")).toBe(false);
    expect(isValidSandAgentId("a/b")).toBe(false);
    expect(isValidSandAgentId("a\\b")).toBe(false);
    expect(isValidSandAgentId(" bot")).toBe(false);
    expect(isValidSandAgentId(".")).toBe(false);
    expect(isValidSandAgentId("..")).toBe(false);
  });

  it("lists every profile and ignores a file and a description", () => {
    const root = rootWith(["zeta", "alpha"]);
    writeFileSync(join(root, "agents", "notes.txt"), "not a profile", "utf8");
    writeFileSync(
      join(root, "agents", "alpha", "profile.json"),
      JSON.stringify({ description: "SECRET-PROMPT" }),
      "utf8",
    );
    const ids = listProfileAgentIds(root);
    expect(ids).toEqual(["alpha", "zeta"]);
    expect(JSON.stringify(ids)).not.toContain("SECRET-PROMPT");
  });

  it("reads the current profile only when that agent directory exists", () => {
    const root = rootWith(["research-bot"], "research-bot");
    expect(readActiveProfileAgent(root)).toBe("research-bot");
    writeFileSync(join(root, "agents", "active-agent.json"), JSON.stringify({ activeAgentId: "../x" }), "utf8");
    expect(readActiveProfileAgent(root)).toBeUndefined();
    writeFileSync(join(root, "agents", "active-agent.json"), JSON.stringify({ activeAgentId: "missing" }), "utf8");
    expect(readActiveProfileAgent(root)).toBeUndefined();
  });

  it("defaults to the current profile, and --all-profiles expands every profile", () => {
    const sandRoot = rootWith(["ops-bot", "research-bot"], "research-bot");
    expect(selectAnnounceAgents({ allProfiles: false, sandRoot }).agents).toEqual(["research-bot"]);
    expect(
      selectAnnounceAgents({ allProfiles: false, configuredAgent: "named-bot", sandRoot }).agents,
    ).toEqual(["named-bot"]);
    expect(
      selectAnnounceAgents({
        allProfiles: false,
        announceAgents: ["from-env"],
        configuredAgent: "named-bot",
        sandRoot,
      }).agents,
    ).toEqual(["from-env"]);
    expect(selectAnnounceAgents({ allProfiles: true, configuredAgent: "named-bot", sandRoot }).agents).toEqual([
      "ops-bot",
      "research-bot",
    ]);
    const empty = mkdtempSync(join(tmpdir(), "grokbot-profiles-empty-"));
    expect(selectAnnounceAgents({ allProfiles: true, sandRoot: empty }).problem).toContain("no profiles");
    expect(selectAnnounceAgents({ allProfiles: false, sandRoot: empty }).agents).toEqual(["grokbot-agent"]);
  });
});
