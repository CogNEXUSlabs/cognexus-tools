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
import type { FetchLike } from "./client.js";
import { enrollInstance } from "./enroll.js";
import { gateToolCall, type SkillConfig } from "./gate.js";

/**
 * How long an announce or enroll still in flight once `decide` has its
 * verdict may run on before it is cut off. They are telemetry: the exit,
 * which carries the verdict, must not wait out their own 10-second timeout.
 */
const TELEMETRY_GRACE_MS = 2_000;

/** Aborting it ends every request this CLI has made (see `fetchImpl`). */
const cutOff = new AbortController();

/** A signal that aborts when either of two does, with that one's reason. */
function either(a: AbortSignal | undefined, b: AbortSignal): AbortSignal {
  if (!a) return b;
  const both = new AbortController();
  for (const signal of [a, b]) {
    if (signal.aborted) {
      both.abort(signal.reason);
      break;
    }
    signal.addEventListener("abort", () => both.abort(signal.reason), { once: true });
  }
  return both.signal;
}

/**
 * Global fetch, with each request also ended by `cutOff`: a request still in
 * flight holds the process open.
 */
const fetchImpl: FetchLike | undefined =
  typeof globalThis.fetch === "function"
    ? (url, init) =>
        (globalThis.fetch as unknown as FetchLike)(url, {
          ...init,
          signal: either(init.signal, cutOff.signal),
        })
    : undefined;

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
    // Unset without the flag: the gate reads COGNEXUS_API_BASE_URL itself and
    // names it, not the flag, when a request fails.
    baseUrl: flag(args, "--base-url") || undefined,
    baseUrlSource: "--base-url",
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
    const out = await announceInstance({ ...cfg, announce: true }, fetchImpl, log, cfg.agentDid);
    return out.ok ? 0 : 2;
  }

  if (cmd === "enroll") {
    const out = await enrollInstance({ ...cfg, enroll: true }, fetchImpl, log, cfg.agentDid);
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
    fetchImpl,
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

// Not process.exit(): on Windows, ending the process that way just after an
// enroll or announce that ran beside the decision has finished can abort
// Node (a libuv assertion, exit code 3221226505) instead of exiting with
// this code. The process ends by itself once nothing is in flight. Idle
// keep-alive connections do not hold it, and whatever still runs is cut off
// after TELEMETRY_GRACE_MS. The timer is unref'd and holds nothing open.
process.exitCode = await main(process.argv.slice(2));
setTimeout(
  () => cutOff.abort(new DOMException("the CLI is exiting", "AbortError")),
  TELEMETRY_GRACE_MS,
).unref();
