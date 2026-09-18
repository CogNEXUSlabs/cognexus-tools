/**
 * CogNEXUS Grok Bot skill — cooperative pattern C tool gate.
 *
 * Install from a CogNEXUS checkout (`sdk/grokbot/SKILL.md` into the Bot's
 * skills folder, or `npx @cognexuslabs/grokbot-artzain decide …`). This
 * repository does not publish to npm (Trusted Publishing lives on
 * cognexus-tools). There is no host `before_tool_call` intercept; the
 * Bot has to call the gate.
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
