#!/usr/bin/env python3
"""Measure decide latency from where you run it.

Makes real decisions against an ArtzAIn engine with your own API key and
reports the median, 95th and 99th percentile of the round trip and of the
engine's own time (its ``latency_ms``). It sends the same short request the
hosted latency probes send (status.cognexuslabs.ai, "Decide latency"), so
your numbers and the published ones compare like for like.

    export COGNEXUS_API_KEY=cnx_...
    python tools/bench_decide.py                  # 50 requests on one warm connection
    python tools/bench_decide.py --cold           # and 50 each on a new connection
    python tools/bench_decide.py --requests 200 --json
    python tools/bench_decide.py --url http://127.0.0.1:8000   # an engine of your own

Every request is a real decision: sealed into your audit chain and counted
against your plan, so a plan with a daily cap spends it. Standard library
only, Python 3.10 or later. The key is read from the environment and never
printed.
"""
from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import ssl
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

DEFAULT_URL = "https://app.cognexuslabs.ai"
DECIDE_PATH = "/api/v1/decisions"
PUBLISHED = "https://status.cognexuslabs.ai/#latency"
USER_AGENT = "artzain-bench-decide/1"
TIMEOUT_SECONDS = 10.0
#: A 429 is waited out this many times per request before it counts as a failure.
RETRIES_ON_429 = 3
#: The longest Retry-After honoured, in seconds.
MAX_WAIT = 60.0
#: After this many failures in a row the run stops: the engine, the key or
#: the network is the problem, not the latency.
MAX_CONSECUTIVE_FAILURES = 10
PERCENTILES = (50, 95, 99)

#: What the hosted probes ask the engine to decide: harmless text, allowed
#: by any policy. The same request here, so the figures compare.
REQUEST_TEMPLATE = {
    "agent_did": "bench:latency",
    "action": "latency_probe",
    "target": "probe:latency",
    "payload": "Latency probe: no action is taken on this decision.",
    "payload_kind": "user_input",
    "surface": "sdk",
}

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def percentile(values: Sequence[float], pct: float) -> Optional[float]:
    """Nearest-rank percentile; None on no values."""
    vals = sorted(values)
    if not vals:
        return None
    rank = max(1, math.ceil(pct / 100.0 * len(vals)))
    return float(vals[min(rank, len(vals)) - 1])


def request_body() -> bytes:
    return json.dumps(REQUEST_TEMPLATE).encode("utf-8")


def decide(conn: Any, key: str, body: bytes, *,
           clock: Callable[[], float] = time.perf_counter) -> Dict[str, Any]:
    """One decision on *conn*: the client's time, the engine's, and whether
    it worked. Raises nothing: a failure is a result, with its reason and,
    on a 429, how long the engine asked us to wait."""
    started = clock()
    try:
        conn.request("POST", DECIDE_PATH, body=body, headers={
            "Content-Type": "application/json",
            "X-Api-Key": key,
            "User-Agent": USER_AGENT,
        })
        answer = conn.getresponse()
        raw = answer.read()
        elapsed_ms = (clock() - started) * 1000.0
    except (OSError, http.client.HTTPException) as exc:
        return {"ok": False, "reason": type(exc).__name__}
    if answer.status == 429:
        try:
            wait = float(answer.getheader("Retry-After") or 1)
        except ValueError:
            wait = 1.0
        return {"ok": False, "reason": "HTTP 429", "retry_after": max(0.0, min(wait, MAX_WAIT))}
    if answer.status != 200:
        return {"ok": False, "reason": f"HTTP {answer.status}"}
    try:
        server_ms = float(json.loads(raw.decode("utf-8"))["latency_ms"])
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return {"ok": False, "reason": "unreadable answer"}
    return {"ok": True, "client_ms": elapsed_ms, "server_ms": server_ms}


def measure(make_conn: Callable[[], Any], key: str, requests: int, *, cold: bool,
            sleep: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.perf_counter) -> List[Dict[str, Any]]:
    """*requests* decisions: each on a new connection when *cold*, else all
    on one. A 429 is waited out and the request made again; any other
    failure is recorded and the next request made, until
    :data:`MAX_CONSECUTIVE_FAILURES` in a row end the run."""
    body = request_body()
    results: List[Dict[str, Any]] = []
    conn = None if cold else make_conn()
    failures_in_a_row = 0
    try:
        for _ in range(requests):
            if cold:
                if conn is not None:
                    conn.close()
                conn = make_conn()
            result = decide(conn, key, body, clock=clock)
            for _retry in range(RETRIES_ON_429):
                if result.get("reason") != "HTTP 429":
                    break
                sleep(result["retry_after"])
                result = decide(conn, key, body, clock=clock)
            results.append(result)
            failures_in_a_row = 0 if result["ok"] else failures_in_a_row + 1
            if failures_in_a_row >= MAX_CONSECUTIVE_FAILURES:
                break
    finally:
        if conn is not None:
            conn.close()
    return results


def _stats(values: Sequence[float]) -> Dict[str, Any]:
    out: Dict[str, Any] = {f"p{p}": percentile(values, p) for p in PERCENTILES}
    out["min"] = min(values) if values else None
    out["samples"] = len(values)
    return {k: (round(v, 1) if isinstance(v, float) else v) for k, v in out.items()}


def summarize(results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Round trip and engine time percentiles over the calls that worked,
    and the failures by reason."""
    worked = [r for r in results if r["ok"]]
    failed: Dict[str, int] = {}
    for r in results:
        if not r["ok"]:
            failed[r["reason"]] = failed.get(r["reason"], 0) + 1
    return {
        "round_trip": _stats([r["client_ms"] for r in worked]),
        "engine": _stats([r["server_ms"] for r in worked]),
        "failed": failed,
    }


def _ms(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{round(value):d} ms"


def format_block(title: str, summary: Dict[str, Any]) -> str:
    lines = [title, f"{'':18}{'p50':>9}{'p95':>9}{'p99':>9}{'min':>9}{'samples':>9}"]
    for label, key in (("round trip", "round_trip"), ("engine time", "engine")):
        s = summary[key]
        lines.append(f"{label:18}{_ms(s['p50']):>9}{_ms(s['p95']):>9}{_ms(s['p99']):>9}"
                     f"{_ms(s['min']):>9}{s['samples']:>9}")
    if summary["failed"]:
        lines.append("failed: " + ", ".join(f"{n} x {reason}" for reason, n in sorted(summary["failed"].items())))
    return "\n".join(lines)


def https_connection(url: str) -> Callable[[], Any]:
    """A factory for connections to *url*: https anywhere, http only to
    this machine (an engine of your own, such as ``artzain local``)."""
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise ValueError("--url needs a host, such as https://app.cognexuslabs.ai")
    if parts.scheme == "https":
        context = ssl.create_default_context()
        return lambda: http.client.HTTPSConnection(host, parts.port or 443, timeout=TIMEOUT_SECONDS,
                                                   context=context)
    if parts.scheme == "http" and host in LOCAL_HOSTS:
        return lambda: http.client.HTTPConnection(host, parts.port or 80, timeout=TIMEOUT_SECONDS)
    raise ValueError("--url must be https, or http to this machine only: the key travels with every request")


def main(argv: Sequence[str], environ: Dict[str, str] = os.environ,
         make_conn: Optional[Callable[[str], Callable[[], Any]]] = None,
         sleep: Callable[[float], None] = time.sleep, out: Any = sys.stdout) -> int:
    ap = argparse.ArgumentParser(prog="bench_decide.py",
                                 description="Measure decide latency from where you run it.")
    ap.add_argument("--url", default=DEFAULT_URL, help=f"the engine (default {DEFAULT_URL})")
    ap.add_argument("--requests", type=int, default=50, help="decisions per connection mode (default 50)")
    ap.add_argument("--cold", action="store_true", help="also measure each request on a new connection")
    ap.add_argument("--json", action="store_true", help="print the figures as JSON")
    args = ap.parse_args(argv)
    if args.requests < 1:
        ap.error("--requests must be at least 1")
    key = (environ.get("COGNEXUS_API_KEY") or "").strip()
    if not key:
        print("COGNEXUS_API_KEY is not set: export your Decision API key first.", file=sys.stderr)
        return 2
    try:
        factory = (make_conn or https_connection)(args.url)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    report: Dict[str, Any] = {"url": args.url, "requests": args.requests, "warm": None, "cold": None}
    report["warm"] = summarize(measure(factory, key, args.requests, cold=False, sleep=sleep))
    if args.cold:
        report["cold"] = summarize(measure(factory, key, args.requests, cold=True, sleep=sleep))
    measured = any(report[mode] and report[mode]["round_trip"]["samples"] for mode in ("warm", "cold"))

    if args.json:
        print(json.dumps(report, indent=2), file=out)
    else:
        print(f"Decide latency against {args.url}, {args.requests} request(s) per mode\n", file=out)
        print(format_block("warm connection (one connection, the request alone)", report["warm"]), file=out)
        if report["cold"]:
            print("", file=out)
            print(format_block("new connection (DNS, TCP, TLS and the request)", report["cold"]), file=out)
        print("\nRound trip is what this machine saw; engine time is what the engine reports\n"
              "spending from the start of the decision to its seal. Each request was a real\n"
              f"decision, counted against your plan. Published figures: {PUBLISHED}", file=out)
    if not measured:
        print("No decision succeeded; see the failures above.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
