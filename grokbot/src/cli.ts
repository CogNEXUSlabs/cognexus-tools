#!/usr/bin/env node
/**
 * Cooperative CLI for a Grok Bot skill.
 *
 *   grokbot-artzain decide --action send_email --target mailbox --payload '{"tool":"send_email"}'
 *   grokbot-artzain announce
 *   grokbot-artzain enroll
 *
 * Exit 0 = allow. Exit 2 = deny / review / engine refusal (fail closed).
 * Announce and enroll never change the exit code of `decide`.
 */

import { announceInstance } from "./announce.js";
import { enrollInstance } from "./enroll.js";
import { gateToolCall, type SkillConfig } from "./gate.js";

function env(name: string): string {
  return (process.env[name] || "").trim();
}

function flag(args: string[], name: string): string {
  const i = args.indexOf(name);
  if (i < 0 || i + 1 >= args.length) return "";
  return args[i + 1] ?? "";
}

function has(args: string[], name: string): boolean {
  return args.includes(name);
}

function configFromEnv(args: string[]): SkillConfig {
  const skills = env("GROKBOT_ANNOUNCE_SKILLS");
  const agents = env("GROKBOT_ANNOUNCE_AGENTS");
  return {
    apiKey: flag(args, "--api-key") || env("COGNEXUS_API_KEY"),
    baseUrl: flag(args, "--base-url") || env("COGNEXUS_API_BASE_URL"),
    agentDid: flag(args, "--agent-did") || env("GROKBOT_AGENT_ID") || env("COGNEXUS_AGENT_DID"),
    instance: flag(args, "--instance") || env("GROKBOT_INSTANCE"),
    announce: has(args, "--announce") || env("GROKBOT_ANNOUNCE") === "true",
    enroll: !(has(args, "--no-enroll") || env("GROKBOT_ENROLL") === "false"),
    enrollToken: flag(args, "--enroll-token") || env("GROKBOT_ENROLL_TOKEN") || undefined,
    announceAgents: agents ? agents.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
    announceSkills: skills ? skills.split(",").map((s) => s.trim()).filter(Boolean) : ["artzain"],
  };
}

async function main(argv: string[]): Promise<number> {
  const cmd = argv[0] || "decide";
  const args = argv.slice(1);
  const cfg = configFromEnv(args);
  const log = (msg: string) => {
    try {
      console.error(msg);
    } catch {
      /* ignore */
    }
  };

  if (cmd === "announce") {
    const out = await announceInstance({ ...cfg, announce: true }, undefined, log, cfg.agentDid);
    return out.ok ? 0 : 2;
  }

  if (cmd === "enroll") {
    const out = await enrollInstance({ ...cfg, enroll: true }, undefined, log, cfg.agentDid);
    if (out.ok) {
      try {
        console.log(JSON.stringify({
          adapter: out.adapter,
          decision: out.decision,
          envelope: out.envelope ?? null,
        }));
      } catch {
        /* ignore */
      }
      return 0;
    }
    return 2;
  }

  if (cmd !== "decide") {
    log("usage: grokbot-artzain decide|announce|enroll [--action …] [--target …] [--payload '{…}'] [--enroll-token …]");
    return 2;
  }

  const action = flag(args, "--action") || "unknown_tool";
  const payloadRaw = flag(args, "--payload");
  const result = await gateToolCall(
    { ...cfg, enrollToken: undefined },
    {
      toolName: action,
      target: flag(args, "--target") || undefined,
      payload: payloadRaw || undefined,
      toolCallId: flag(args, "--request-id") || undefined,
      agentDid: cfg.agentDid,
    },
  );
  if (result.allow) {
    try {
      console.log(JSON.stringify({ outcome: "allow", decision_id: result.decision.decision_id }));
    } catch {
      /* ignore */
    }
    return 0;
  }
  try {
    console.log(JSON.stringify({ outcome: result.outcome || "deny", error: result.blockReason }));
  } catch {
    /* ignore */
  }
  return 2;
}

process.exit(await main(process.argv.slice(2)));
