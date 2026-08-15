#!/usr/bin/env python3
"""Render the CogNEXUS agent-workflow architecture diagram.

Shows where the ``artzain`` PyPI package sits inside a user's agent
pipeline: four independent safety chokepoints (static prompt defence,
runtime input screening, runtime output / destructive-action guard +
kill switch) plus a cross-cutting audit & telemetry rail to the
CogNEXUS dashboard.

Usage::

    python agent_workflow_architecture.py            # writes agent_workflow_architecture.pdf
    python agent_workflow_architecture.py -o out.pdf

Requires the Graphviz ``dot`` binary and the ``graphviz`` Python bindings
(``conda install -c conda-forge graphviz python-graphviz``).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import graphviz

# ── Palette ────────────────────────────────────────────────────────────────
COG = "#0E7C86"        # CogNEXUS chokepoint fill (teal)
COG_BORDER = "#0A5A61"
COG_LIGHT = "#E6F4F5"  # build-time / audit light teal
USER = "#334155"       # user-owned agent components (slate)
USER_LIGHT = "#F1F5F9"
DASH = "#B45309"       # dashboard (amber)
DASH_LIGHT = "#FEF3C7"
DANGER = "#B91C1C"     # blocked / killed edges
INK = "#0F172A"

FONT = "Helvetica"


def _label(title: str, subtext: str = "", *, title_color: str = "white",
           sub_color: str = "#CBD5E1") -> str:
    """HTML-like label: bold layer name with small function-name subtext."""
    if subtext:
        return (
            f'<<b><font color="{title_color}">{title}</font></b>'
            f'<br/><font point-size="9" color="{sub_color}">{subtext}</font>>'
        )
    return f'<<b><font color="{title_color}">{title}</font></b>>'


def build() -> graphviz.Digraph:
    g = graphviz.Digraph("artzain_agent_workflow", format="pdf")
    g.attr(
        rankdir="LR",
        splines="spline",
        nodesep="0.45",
        ranksep="0.75",
        bgcolor="white",
        fontname=FONT,
        labelloc="t",
        label=(
            '<<b><font point-size="20" color="#0F172A">'
            "CogNEXUS Decision Architecture</font></b>"
            '<br/><font point-size="11" color="#475569">'
            "Where the <b>artzain</b> PyPI package sits in your agent pipeline &#8212; "
            "four independent safety chokepoints + audit telemetry</font>>"
        ),
    )
    g.attr("node", fontname=FONT, fontsize="12", style="filled",
           penwidth="1.4", margin="0.18,0.12")
    g.attr("edge", fontname=FONT, fontsize="9", color=INK, penwidth="1.3")

    # ── Build / deploy time: static prompt defence (feeds the system prompt) ──
    with g.subgraph(name="cluster_build") as c:
        c.attr(label="  BUILD / DEPLOY TIME", labeljust="l",
               fontname=FONT, fontsize="11", fontcolor=COG_BORDER,
               style="rounded,filled,dashed", color=COG_BORDER, fillcolor=COG_LIGHT)
        c.node(
            "prompt_defense",
            _label("Static Prompt Defence",
                   "augment_system_prompt() · evaluate_system_prompt()<br/>"
                   "OWASP LLM Top-10 grade A–F · RuleSet.FINANCIAL / LEGAL",
                   title_color=INK, sub_color="#0A5A61"),
            shape="box", style="rounded,filled", fillcolor="white",
            color=COG_BORDER, fontcolor=INK,
        )
        c.node(
            "policy",
            _label("Client Policy Enforcement",
                   "screen_client_policy() · load_client_policy_rules()<br/>"
                   "tenant HR / legal / business policy docs",
                   title_color=INK, sub_color="#0A5A61"),
            shape="box", style="rounded,filled", fillcolor="white",
            color=COG_BORDER, fontcolor=INK,
        )

    # ── Request time ────────────────────────────────────────────────────────
    g.node(
        "user",
        _label("User / Untrusted Input",
               "chat · RAG content · tabular payloads",
               title_color="white", sub_color="#E2E8F0"),
        shape="box", style="rounded,filled", fillcolor=USER, color="#1E293B",
    )
    g.node(
        "input_guard",
        _label("Runtime Input Screening",
               "screen_user_input() · should_block()<br/>"
               "screen_external_content() · screen_tabular_payload()"),
        shape="box", style="rounded,filled", fillcolor=COG, color=COG_BORDER,
    )

    # ── The agent / LLM (user-owned) ──────────────────────────────────────────
    with g.subgraph(name="cluster_agent") as c:
        c.attr(label="  YOUR AGENT / LLM", labeljust="l",
               fontname=FONT, fontsize="11", fontcolor="#1E293B",
               style="rounded,filled", color="#1E293B", fillcolor=USER_LIGHT)
        c.node(
            "agent",
            _label("Agent Orchestrator + Model",
                   "system prompt + tools · reasoning / tool-call loop",
                   title_color="white", sub_color="#E2E8F0"),
            shape="box", style="rounded,filled", fillcolor=USER, color="#1E293B",
        )

    # ── Response time: output guard + kill switch (one chokepoint cluster) ─────
    with g.subgraph(name="cluster_response") as c:
        c.attr(label="  RESPONSE TIME · TOOL-CALL GUARD", labeljust="l",
               fontname=FONT, fontsize="11", fontcolor=COG_BORDER,
               style="rounded,filled,dashed", color=COG_BORDER, fillcolor=COG_LIGHT)
        c.node(
            "output_guard",
            _label("Destructive-Action Guard",
                   "screen_action() · screen_agent_action()<br/>"
                   "SQL / shell / git / cloud · severity low→critical"),
            shape="box", style="rounded,filled", fillcolor=COG, color=COG_BORDER,
        )
        c.node(
            "kill",
            _label("Agent Kill Switch",
                   "raise_if_killed() · trip() / trip_global()<br/>"
                   "auto-trips on CRITICAL → AgentKilledError"),
            shape="box", style="rounded,filled", fillcolor=COG, color=COG_BORDER,
        )

    # ── Action execution (user-owned) ─────────────────────────────────────────
    g.node(
        "action",
        _label("Action Execution",
               "database · shell · git · cloud APIs",
               title_color="white", sub_color="#E2E8F0"),
        shape="box", style="rounded,filled", fillcolor=USER, color="#1E293B",
    )

    # ── Cross-cutting: audit + telemetry → dashboard ──────────────────────────
    g.node(
        "audit",
        _label("Audit &amp; Telemetry",
               "append-only JSONL · verify_chain()<br/>"
               "post_sdk_event() · post_generation_outcome()",
               title_color=INK, sub_color="#0A5A61"),
        shape="box", style="rounded,filled", fillcolor=COG_LIGHT, color=COG_BORDER,
        fontcolor=INK,
    )
    g.node(
        "dashboard",
        _label("CogNEXUS Dashboard",
               "Event Logs · Token-to-Outcome leaderboard",
               title_color="white", sub_color="#FEF3C7"),
        shape="box", style="rounded,filled", fillcolor=DASH, color="#7C2D12",
    )

    # ── Main left→right flow ──────────────────────────────────────────────────
    g.edge("user", "input_guard", label="request")
    g.edge("input_guard", "agent", label="allowed", color=COG_BORDER)
    g.edge("agent", "output_guard", label="proposed\naction")
    g.edge("output_guard", "kill", label="severity", color=COG_BORDER)
    g.edge("kill", "action", label="execute", color=COG_BORDER)

    # prompt defence feeds the agent's system prompt (kept as real constraints
    # so the build-time cluster sits just left of the agent, not across the page)
    g.edge("prompt_defense", "agent", label="hardened\nsystem prompt",
           color=COG_BORDER, style="dashed")
    g.edge("policy", "agent", style="dashed", color=COG_BORDER)

    # block / kill paths (refusal feedback)
    g.edge("input_guard", "user", label="blocked", color=DANGER,
           fontcolor=DANGER, style="dashed", constraint="false")
    g.edge("kill", "agent", label="CRITICAL →\nAgentKilledError", color=DANGER,
           fontcolor=DANGER, style="dashed", constraint="false")

    # audit rail (telemetry from every chokepoint)
    for src in ("input_guard", "agent", "output_guard", "kill"):
        g.edge(src, "audit", style="dotted", color=COG_BORDER, arrowsize="0.7",
               constraint="false")
    g.edge("audit", "dashboard", label="ingest", color="#7C2D12")

    # keep audit + dashboard on a lower rank
    with g.subgraph() as s:
        s.attr(rank="sink")
        s.node("audit")
        s.node("dashboard")

    return g


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-o", "--output",
        default=str(Path(__file__).with_name("agent_decision_architecture.pdf")),
        help="Output file path (extension sets the format; default PDF).",
    )
    args = ap.parse_args()

    out = Path(args.output)
    fmt = (out.suffix.lstrip(".") or "pdf").lower()
    g = build()
    g.format = fmt
    # render() appends the format extension; strip it from the stem we pass.
    rendered = g.render(filename=out.with_suffix(""), cleanup=True)
    print(f"Wrote {rendered}")


if __name__ == "__main__":
    main()
