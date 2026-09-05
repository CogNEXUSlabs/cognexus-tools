/**
 * CogNEXUS OpenClaw plugin — pattern C tool gate.
 *
 * Install from a CogNEXUS checkout (`openclaw plugins install ./sdk/openclaw`).
 * This repository does not publish to ClawHub (Trusted Publishing lives on
 * cognexus-tools). Envelope pattern B is still the models.providers snippet.
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { handleBeforeToolCall, HOOK_TIMEOUT_MS } from "./gate.js";

export default definePluginEntry({
  id: "artzain-tool-gate",
  name: "CogNEXUS tool gate",
  description:
    "Clear OpenClaw host tools through the CogNEXUS Decision API before they run.",
  register(api: {
    on: (
      name: "before_tool_call",
      handler: (event: unknown, ctx: unknown) => Promise<unknown>,
      opts?: { timeoutMs?: number },
    ) => void;
  }) {
    api.on(
      "before_tool_call",
      async (event, ctx) =>
        handleBeforeToolCall(
          event as Parameters<typeof handleBeforeToolCall>[0],
          ctx as Parameters<typeof handleBeforeToolCall>[1],
        ),
      { timeoutMs: HOOK_TIMEOUT_MS },
    );
  },
});
