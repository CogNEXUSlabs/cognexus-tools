/**
 * CogNEXUS Grok Bot skill — cooperative pattern C tool gate.
 *
 * Install with `npm install -g @cognexuslabs/grokbot-artzain` and add
 * `SKILL.md` to the Bot as a skill (README, "Set it up"). This repository
 * does not publish to npm (Trusted Publishing lives on cognexus-tools).
 * There is no host `before_tool_call` intercept; the Bot has to call the
 * gate. `handleBeforeToolCall` is that gate in the shape a host hook calls.
 * This package does not register the hook.
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

export { gateToolCall, handleBeforeToolCall, resetAnnounceForTests, resetEnrollForTests } from "./gate.js";
export type { BlockResult, GateInput, GateResult, SkillConfig, ToolCallCtx, ToolCallEvent } from "./gate.js";

export { listenMcpHttp, serveMcpHttp, serveMcpStdio } from "./mcp/server.js";
export type { ListeningMcp, McpConfig, ServeOptions } from "./mcp/server.js";
