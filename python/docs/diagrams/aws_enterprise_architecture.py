#!/usr/bin/env python3
"""Render the CogNEXUS AWS Enterprise Agent Architecture diagram.

Shows an end-to-end enterprise agent deployment on AWS, with the
``artzain`` PyPI package clearly marked as the safety layer at each
chokepoint in the stack.

Usage::

    python aws_enterprise_architecture.py           # writes aws_enterprise_architecture.pdf
    python aws_enterprise_architecture.py -o out.png

Requires the Graphviz ``dot`` binary and the ``graphviz`` Python bindings.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import graphviz

# ── Palette ─────────────────────────────────────────────────────────────────
AWS_ORANGE   = "#FF9900"
AWS_ORANGE_B = "#C77A00"   # border
AWS_DARK     = "#232F3E"
AWS_FILL     = "#FFF8EE"   # pale orange
AWS_PURPLE_F = "#F5F0FF"
AWS_PURPLE_B = "#6B21A8"
AWS_BLUE_F   = "#EFF6FF"
AWS_BLUE_B   = "#1D4ED8"
AWS_GREEN_F  = "#ECFDF5"
AWS_GREEN_B  = "#065F46"

COG          = "#0E7C86"
COG_BORDER   = "#0A5A61"
COG_LIGHT    = "#E6F4F5"
COG_AMBER    = "#B45309"
COG_AMBER_B  = "#7C2D12"

DANGER       = "#DC2626"
INK          = "#0F172A"
GRAY_F       = "#F8FAFC"
GRAY_B       = "#94A3B8"

FONT = "Helvetica"


def _html(title: str, subtext: str = "", *,
          title_color: str = "white", sub_color: str = "#CBD5E1") -> str:
    """Return a Graphviz HTML-like label with bold title + small subtext."""
    if subtext:
        return (
            f'<<b><font color="{title_color}">{title}</font></b>'
            f'<br/><font point-size="9" color="{sub_color}">{subtext}</font>>'
        )
    return f'<<b><font color="{title_color}">{title}</font></b>>'


def _aws(title: str, subtext: str = "", service: str = "") -> str:
    """AWS node label: dark title, grey service tag, body subtext."""
    inner = f'<b><font color="{INK}">{title}</font></b>'
    if service:
        inner += f'<br/><font point-size="8" color="#6B7280">{service}</font>'
    if subtext:
        inner += f'<br/><font point-size="9" color="#374151">{subtext}</font>'
    return f'<{inner}>'


def build() -> graphviz.Digraph:
    g = graphviz.Digraph("aws_artzain_enterprise", format="pdf")
    g.attr(
        rankdir="TB",
        splines="spline",
        nodesep="0.55",
        ranksep="0.75",
        bgcolor="white",
        fontname=FONT,
        labelloc="t",
        label=(
            '<<b><font point-size="20" color="#0F172A">'
            "Enterprise Agent Architecture on AWS</font></b>"
            '<br/><font point-size="11" color="#475569">'
            "Where <b>CogNEXUS</b> fits as the safety layer "
            "in your agent deployment stack</font>>"
        ),
    )
    g.attr("node", fontname=FONT, fontsize="11", style="filled",
           penwidth="1.5", margin="0.20,0.13")
    g.attr("edge", fontname=FONT, fontsize="9", penwidth="1.3", color=INK)

    # ── Tier 1: Clients ───────────────────────────────────────────────────────
    with g.subgraph(name="cluster_clients") as c:
        c.attr(label="CLIENTS", labeljust="c",
               style="rounded,filled,dashed", color=GRAY_B, fillcolor=GRAY_F,
               fontname=FONT, fontsize="10", fontcolor=GRAY_B)
        c.node("webapp",
               _aws("Web / Mobile App", "browser · REST · WebSocket"),
               shape="box", style="rounded,filled",
               fillcolor=GRAY_F, color=GRAY_B)
        c.node("extapi",
               _aws("API Client / CI-CD", "internal tools · scheduled jobs"),
               shape="box", style="rounded,filled",
               fillcolor=GRAY_F, color=GRAY_B)

    # ── Tier 2: Edge ──────────────────────────────────────────────────────────
    with g.subgraph(name="cluster_edge") as c:
        c.attr(label="EDGE", labeljust="c",
               style="rounded,filled,dashed", color=AWS_ORANGE_B, fillcolor=AWS_FILL,
               fontname=FONT, fontsize="10", fontcolor=AWS_ORANGE_B)
        c.node("cloudfront",
               _aws("CloudFront", "CDN · TLS termination · geo-block",
                    "Amazon CloudFront"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_FILL, color=AWS_ORANGE_B)
        c.node("waf",
               _aws("WAF", "IP allow/block · rate limit · bot control",
                    "AWS WAF"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_FILL, color=AWS_ORANGE_B)

    # ── Tier 3: Ingress ───────────────────────────────────────────────────────
    with g.subgraph(name="cluster_ingress") as c:
        c.attr(label="INGRESS", labeljust="c",
               style="rounded,filled,dashed", color=AWS_ORANGE_B, fillcolor=AWS_FILL,
               fontname=FONT, fontsize="10", fontcolor=AWS_ORANGE_B)
        c.node("apigw",
               _aws("API Gateway", "auth (Cognito/JWT) · routing · throttling",
                    "Amazon API Gateway"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_FILL, color=AWS_ORANGE_B)
        c.node("alb",
               _aws("Load Balancer", "health checks · SSL offload",
                    "Application LB"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_FILL, color=AWS_ORANGE_B)

    # ────────────────────────────────────────────────────────────────────────
    # COGNEXUS LAYER 1 — Input Screening (between ingress and compute)
    # ────────────────────────────────────────────────────────────────────────
    g.node("cog_input",
           _html("CogNEXUS  ·  Input Screening",
                 "screen_user_input() · should_block() · screen_external_content()<br/>"
                 "Injection / jailbreak / override / credential-exfiltration detection<br/>"
                 "Blocks the request <i>before</i> the LLM is called"),
           shape="box", style="rounded,filled",
           fillcolor=COG, color=COG_BORDER)

    # ── Tier 4: Agent Compute  (VPC — Private Subnets) ───────────────────────
    with g.subgraph(name="cluster_compute") as c:
        c.attr(label="AGENT COMPUTE  (VPC — Private Subnets)", labeljust="l",
               style="rounded,filled", color=AWS_BLUE_B, fillcolor=AWS_BLUE_F,
               fontname=FONT, fontsize="10", fontcolor=AWS_BLUE_B)

        c.node("cog_prompt",
               _html("CogNEXUS  ·  Static Prompt Defence",
                     "augment_system_prompt() · evaluate_system_prompt()<br/>"
                     "OWASP LLM Top-10 grade A&#8211;F · RuleSet.FINANCIAL / LEGAL<br/>"
                     "screen_client_policy() &#8212; injects hardened system prompt",
                     title_color=INK, sub_color=COG_BORDER),
               shape="box", style="rounded,filled",
               fillcolor=COG_LIGHT, color=COG_BORDER)

        c.node("agent_orch",
               _aws("Agent Orchestrator", "multi-step reasoning · tool-call loop",
                    "ECS Fargate / Lambda / EKS"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_BLUE_F, color=AWS_BLUE_B)

        c.node("secrets",
               _aws("Secrets Manager", "API keys · DB creds · rotation",
                    "AWS Secrets Manager"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_FILL, color=AWS_ORANGE_B)

        c.node("iam",
               _aws("IAM Task Roles", "least-privilege · resource-level policies",
                    "AWS IAM"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_FILL, color=AWS_ORANGE_B)

    # ── Tier 5: LLM Inference ─────────────────────────────────────────────────
    with g.subgraph(name="cluster_llm") as c:
        c.attr(label="LLM INFERENCE", labeljust="c",
               style="rounded,filled,dashed", color=AWS_PURPLE_B, fillcolor=AWS_PURPLE_F,
               fontname=FONT, fontsize="10", fontcolor=AWS_PURPLE_B)
        c.node("bedrock",
               _aws("Amazon Bedrock",
                    "Claude 3.5 · Llama 3 · Titan · on-demand / provisioned",
                    "Managed foundation models"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_PURPLE_F, color=AWS_PURPLE_B)
        c.node("ext_llm",
               _aws("External LLM APIs",
                    "OpenAI · Anthropic · Mistral · Cohere",
                    "via NAT Gateway / PrivateLink"),
               shape="box", style="rounded,filled",
               fillcolor=AWS_PURPLE_F, color=AWS_PURPLE_B)

    # ────────────────────────────────────────────────────────────────────────
    # COGNEXUS LAYER 2 — Output Guard + Kill Switch (before any tool executes)
    # ────────────────────────────────────────────────────────────────────────
    g.node("cog_output",
           _html("CogNEXUS  ·  Output Guard  +  Kill Switch",
                 "screen_action() · screen_agent_action() — SQL / shell / git / cloud<br/>"
                 "raise_if_killed() · trip() / trip_global() — panic threshold auto-stop<br/>"
                 "Severity low &#8594; critical  ·  CRITICAL &#8594; AgentKilledError"),
           shape="box", style="rounded,filled",
           fillcolor=COG, color=COG_BORDER)

    # ── Tier 6: Data and Tools  (VPC — Private Subnets) ─────────────────────
    with g.subgraph(name="cluster_data") as c:
        c.attr(label="DATA  &  TOOLS  (VPC — Private Subnets)", labeljust="l",
               style="rounded,filled", color=AWS_GREEN_B, fillcolor=AWS_GREEN_F,
               fontname=FONT, fontsize="10", fontcolor=AWS_GREEN_B)
        c.node("rds",
               _aws("Relational DB", "PostgreSQL · MySQL · Aurora",
                    "Amazon RDS / Aurora"),
               shape="cylinder", style="filled",
               fillcolor="#D1FAE5", color=AWS_GREEN_B)
        c.node("dynamo",
               _aws("Agent Memory / State", "sessions · run history · KV store",
                    "Amazon DynamoDB"),
               shape="cylinder", style="filled",
               fillcolor="#D1FAE5", color=AWS_GREEN_B)
        c.node("opensearch",
               _aws("Vector / RAG Store",
                    "embeddings · semantic search · document chunks",
                    "Amazon OpenSearch / Kendra"),
               shape="cylinder", style="filled",
               fillcolor="#D1FAE5", color=AWS_GREEN_B)
        c.node("elasticache",
               _aws("Prompt Cache", "response cache · session state",
                    "ElastiCache (Redis)"),
               shape="cylinder", style="filled",
               fillcolor="#D1FAE5", color=AWS_GREEN_B)
        c.node("s3",
               _aws("Object Storage", "policy docs · assets · audit logs",
                    "Amazon S3"),
               shape="cylinder", style="filled",
               fillcolor="#D1FAE5", color=AWS_GREEN_B)
        c.node("sqs",
               _aws("Async / Event Bus", "long-running tasks · retries · fan-out",
                    "SQS / EventBridge"),
               shape="box", style="rounded,filled",
               fillcolor="#D1FAE5", color=AWS_GREEN_B)

    # ── Tier 7: Observability and Audit ──────────────────────────────────────
    with g.subgraph(name="cluster_obs") as c:
        c.attr(label="OBSERVABILITY  &  AUDIT", labeljust="c",
               style="rounded,filled,dashed", color=GRAY_B, fillcolor=GRAY_F,
               fontname=FONT, fontsize="10", fontcolor=GRAY_B)
        c.node("cloudwatch",
               _aws("CloudWatch + CloudTrail",
                    "metrics · logs · alarms · API audit trail",
                    "AWS CloudWatch / CloudTrail"),
               shape="box", style="rounded,filled",
               fillcolor=GRAY_F, color=GRAY_B)
        c.node("cog_dash",
               _html("CogNEXUS Dashboard",
                     "Event Logs · Prompt Defence grades · kill-switch alerts<br/>"
                     "Token-to-Outcome leaderboard · post_generation_outcome()",
                     title_color="white", sub_color="#FEF3C7"),
               shape="box", style="rounded,filled",
               fillcolor=COG_AMBER, color=COG_AMBER_B)

    # ── Primary request-flow edges (top → bottom) ─────────────────────────────
    g.edge("webapp",      "cloudfront")
    g.edge("extapi",      "cloudfront")
    g.edge("cloudfront",  "waf")
    g.edge("waf",         "apigw")
    g.edge("apigw",       "alb")
    g.edge("alb",         "cog_input")
    g.edge("cog_input",   "agent_orch",  label="allowed",  color=COG_BORDER)
    g.edge("agent_orch",  "bedrock",     label="LLM call",  color=AWS_PURPLE_B)
    g.edge("agent_orch",  "ext_llm",                       color=AWS_PURPLE_B)
    g.edge("bedrock",     "cog_output",  label="proposed action")
    g.edge("ext_llm",     "cog_output")
    g.edge("cog_output",  "rds",         label="safe\nexecute", color=COG_BORDER)
    g.edge("cog_output",  "dynamo",                             color=COG_BORDER)
    g.edge("cog_output",  "opensearch",  label="RAG\nquery",    color=COG_BORDER)
    g.edge("cog_output",  "s3",                                 color=COG_BORDER)
    g.edge("cog_output",  "sqs",                                color=COG_BORDER)

    # ── Supporting / ancillary edges ──────────────────────────────────────────
    # prompt defence feeds the system prompt at startup (dashed)
    g.edge("cog_prompt", "agent_orch",
           label="hardened\nsystem prompt",
           color=COG_BORDER, style="dashed")
    # agent reads from cache and secrets (dashed, non-constraining)
    g.edge("agent_orch", "elasticache",
           label="cache", color=AWS_GREEN_B, style="dashed", constraint="false")
    g.edge("agent_orch", "secrets",
           style="dashed", color=AWS_ORANGE_B, constraint="false")
    g.edge("agent_orch", "iam",
           style="dashed", color=AWS_ORANGE_B, constraint="false")

    # ── Safety feedback / halt paths (red dashed) ─────────────────────────────
    g.edge("cog_input",  "alb",
           label="blocked", color=DANGER, fontcolor=DANGER,
           style="dashed", constraint="false")
    g.edge("cog_output", "agent_orch",
           label="CRITICAL\nAgentKilledError", color=DANGER, fontcolor=DANGER,
           style="dashed", constraint="false")

    # ── Audit / telemetry rail (dotted) ───────────────────────────────────────
    for src in ("cog_input", "agent_orch", "cog_output"):
        g.edge(src, "cloudwatch",
               style="dotted", color=GRAY_B, arrowsize="0.7", constraint="false")
    for src in ("cog_input", "cog_prompt", "cog_output"):
        g.edge(src, "cog_dash",
               style="dotted", color=COG_BORDER, arrowsize="0.7", constraint="false")

    return g


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "-o", "--output",
        default=str(Path(__file__).with_name("aws_enterprise_architecture.pdf")),
        help="Output path — extension sets the format.",
    )
    args = ap.parse_args()
    out = Path(args.output)
    fmt = (out.suffix.lstrip(".") or "pdf").lower()
    g = build()
    g.format = fmt
    rendered = g.render(filename=out.with_suffix(""), cleanup=True)
    print(f"Wrote {rendered}")


if __name__ == "__main__":
    main()
