import { homedir } from "node:os";
import { posix, win32 } from "node:path";

import { describe, expect, it } from "vitest";

import { defaultActionLog } from "./actionlog.js";

describe("the action log path, the one grokbot-artzain coverage reads", () => {
  it("is ARTZAIN_GATEWAY_LOG when that is set", () => {
    expect(defaultActionLog({ ARTZAIN_GATEWAY_LOG: " /var/log/gw.jsonl " }, "linux")).toBe("/var/log/gw.jsonl");
    expect(defaultActionLog({ ARTZAIN_GATEWAY_LOG: "D:\\logs\\gw.jsonl", APPDATA: "C:\\x" }, "win32")).toBe(
      "D:\\logs\\gw.jsonl",
    );
  });

  it("is under ~/.config on Linux and macOS", () => {
    expect(defaultActionLog({ HOME: "/home/box" }, "linux")).toBe("/home/box/.config/artzain-mcp-gateway/gateway.jsonl");
    expect(defaultActionLog({ HOME: "/Users/jean" }, "darwin")).toBe(
      "/Users/jean/.config/artzain-mcp-gateway/gateway.jsonl",
    );
    expect(defaultActionLog({}, "linux")).toBe(posix.join(homedir(), ".config", "artzain-mcp-gateway", "gateway.jsonl"));
  });

  it("is under %APPDATA% on Windows", () => {
    expect(defaultActionLog({ APPDATA: "C:\\Users\\jean\\AppData\\Roaming" }, "win32")).toBe(
      "C:\\Users\\jean\\AppData\\Roaming\\artzain-mcp-gateway\\gateway.jsonl",
    );
    expect(defaultActionLog({}, "win32")).toBe(
      win32.join(homedir(), "AppData", "Roaming", "artzain-mcp-gateway", "gateway.jsonl"),
    );
  });
});
