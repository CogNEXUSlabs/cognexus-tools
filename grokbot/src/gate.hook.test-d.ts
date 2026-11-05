import { expectTypeOf, test } from "vitest";

import type { FetchLike } from "./client.js";
import {
  gateToolCall,
  handleBeforeToolCall,
  type BlockResult,
  type GateInput,
  type GateResult,
  type SkillConfig,
  type ToolCallCtx,
  type ToolCallEvent,
} from "./gate.js";

test("pins gateToolCall and handleBeforeToolCall", () => {
  expectTypeOf(gateToolCall).toEqualTypeOf<
    (cfg: SkillConfig, input: GateInput, fetchImpl?: FetchLike) => Promise<GateResult>
  >();
  expectTypeOf(handleBeforeToolCall).toEqualTypeOf<
    (event: ToolCallEvent, ctx: ToolCallCtx, fetchImpl?: FetchLike) => Promise<BlockResult | undefined>
  >();
});
