/**
 * CogNEXUS Grok Bot skill — cooperative pattern C tool gate.
 *
 * Install with `npm install -g @cognexuslabs/grokbot-artzain` and add
 * `SKILL.md` to the Bot as a skill (README, "Set it up"). This repository
 * does not publish to npm (Trusted Publishing lives on cognexus-tools).
 * There is no host `before_tool_call` intercept; the Bot has to call the
 * gate.
 */

export {
  DecisionError,
  DEFAULT_BASE_URL,
  DECIDE_TIMEOUT_MS,
  postDecision,
  resolveApiKey,
  resolveBaseUrl,
} from "./client.js";
export type {
  AgentVote,
  DecisionOutcome,
  DecisionResponse,
  FetchLike,
  PostDecisionOptions,
} from "./client.js";

export { announceInstance, ANNOUNCE_TIMEOUT_MS } from "./announce.js";
export type { AnnounceConfig, AnnounceResult } from "./announce.js";

export { enrollInstance, ENROLL_TIMEOUT_MS } from "./enroll.js";
export type { EnrollConfig, EnrollResult } from "./enroll.js";

export { gateToolCall, resetAnnounceForTests, resetEnrollForTests } from "./gate.js";
export type { GateInput, GateResult, SkillConfig } from "./gate.js";
