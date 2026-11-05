import { describe, expect, it } from "vitest";

import { classifyTool, readTaxonomy } from "./taxonomy.js";

/**
 * Connector tool name, the action it must become, arguments, and the target
 * those arguments fill. Twenty names, so a mapping that drops one fails.
 */
const TOOLS: ReadonlyArray<readonly [string, string, Record<string, string>, string]> = [
  ["send_email", "send_email", { to: "ops@example.com" }, "email:mailbox/ops@example.com"],
  ["gmail_send_email", "send_email", { to: "ops@example.com" }, "gmail:message/ops@example.com"],
  ["outlook_send_mail", "send_email", { to: "ops@example.com" }, "outlook:message/ops@example.com"],
  ["compose_email", "send_email", { to: "ops@example.com" }, "email:mailbox/ops@example.com"],
  ["slack_send_message", "send_chat_message", { channel: "C123" }, "slack:channel/C123"],
  ["slack_post_message", "send_chat_message", { channel: "C123" }, "slack:channel/C123"],
  ["post_message", "send_chat_message", { channel: "ops" }, "slack:channel/ops"],
  ["teams_post_message", "send_chat_message", { channel: "general" }, "teams:channel/general"],
  ["send_sms", "send_chat_message", { to: "+15555550100" }, "sms:number/+15555550100"],
  ["send_agent_message", "send_agent_message", { to: "research-bot" }, "agent:bot/research-bot"],
  ["post_to_x", "post_public", { account: "acme" }, "x:post/acme"],
  ["tweet", "post_public", { account: "acme" }, "x:post/acme"],
  ["post_to_linkedin", "post_public", { author: "acme" }, "linkedin:post/acme"],
  ["create_ticket", "create_ticket", { title: "Disk full" }, "ticket:issue/Disk full"],
  ["jira_create_issue", "create_ticket", { project: "OPS" }, "jira:issue/OPS"],
  ["update_ticket", "update_ticket", { id: "OPS-14" }, "ticket:issue/OPS-14"],
  ["create_event", "create_event", { calendar: "primary" }, "calendar:event/primary"],
  ["gcal_create_event", "create_event", { calendar: "primary" }, "google:event/primary"],
  ["update_event", "update_event", { event_id: "evt-9" }, "calendar:event/evt-9"],
  ["purchase", "purchase", { sku: "PAL-200" }, "payment:order/PAL-200"],
  ["place_order", "purchase", { sku: "PAL-200" }, "payment:order/PAL-200"],
  ["pay_invoice", "purchase", { invoice_id: "INV-9" }, "payment:invoice/INV-9"],
  ["wire_transfer", "purchase", { account: "acme" }, "bank:transfer/acme"],
  ["delete_file", "delete_resource", { path: "notes.txt" }, "file:path/notes.txt"],
  ["share_file", "share_resource", { file: "budget.xlsx" }, "drive:file/budget.xlsx"],
  ["write_file", "write_file", { path: "README.md" }, "file:path/README.md"],
  ["run_command", "run_command", { host: "build-1" }, "shell:host/build-1"],
  ["write_repo", "write_repo", { repo: "Quantumskipper/CogNEXUS" }, "github:repo/Quantumskipper/CogNEXUS"],
  ["github_create_pr", "write_repo", { repo: "Quantumskipper/CogNEXUS" }, "github:repo/Quantumskipper/CogNEXUS"],
  ["npm_publish", "publish_package", { name: "grokbot-artzain" }, "npm:package/grokbot-artzain"],
  ["submit_form", "submit_form", { url: "https://example.com/apply" }, "form:page/https://example.com/apply"],
];

describe("taxonomy", () => {
  it("maps connector tool names onto actions and targets", () => {
    expect(TOOLS.length).toBeGreaterThanOrEqual(20);
    for (const [name, action, args, target] of TOOLS) {
      expect(classifyTool(name, args), name).toEqual({ action, target, known: true });
    }
  });

  it("maps an unknown tool name to unknown_tool", () => {
    expect(classifyTool("custom_widget")).toEqual({
      action: "unknown_tool",
      target: "unknown:tool/custom_widget",
      known: false,
    });
  });

  it("leaves the system and kind when the id argument is absent", () => {
    expect(classifyTool("slack_send_message").target).toBe("slack:channel");
  });

  it("lists every action, and every mapped action is one of them", () => {
    const taxonomy = readTaxonomy();
    expect("problem" in taxonomy).toBe(false);
    if ("problem" in taxonomy) return;
    expect(taxonomy.actions).toContain("unknown_tool");
    const named = new Set(taxonomy.actions);
    for (const row of Object.values(taxonomy.tools)) {
      expect(named.has(row.action), row.action).toBe(true);
    }
    const used = new Set(Object.values(taxonomy.tools).map((row) => row.action));
    for (const action of taxonomy.actions) {
      if (action === "unknown_tool") continue;
      expect(used.has(action), action).toBe(true);
    }
  });
});
