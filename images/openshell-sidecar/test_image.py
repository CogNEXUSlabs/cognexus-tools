#!/usr/bin/env python3
"""Does a built sidecar image run the way its Dockerfile says it does?

Usage::

    python images/openshell-sidecar/test_image.py IMAGE --version 0.6.36
    python images/openshell-sidecar/test_image.py IMAGE --version 0.6.36 --platform linux/arm64

Needs `docker` and nothing else. It starts one container from IMAGE with no
network, a read-only root filesystem, every capability dropped and one small
writable mount, and checks that:

* the image runs as uid 10001, not root, and declares no port;
* it holds the `artzain` version it was built for, and no `pip`;
* the sidecar comes up healthy without a network and without writing
  outside its mount;
* the only TCP listener is on loopback, and the gateway's Unix socket is
  there, owner-only, and answers gRPC;
* a governed write is denied when the engine cannot be reached;
* the key it was given is not in its log, and it stops when asked to.

Exits 1 and names every check that failed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid

RUN_DIR = "/run/artzain"
#: A value for the test, not a credential: the container has no network.
TEST_KEY = "cnx_image_test_not_a_real_key"

failures: list[str] = []
#: ``--platform <p>`` for every `docker run`, when one was asked for.
platform: list[str] = []


def check(name: str, ok: bool, detail: object = "") -> None:
    print(("ok    " if ok else "FAIL  ") + name + (f": {detail}" if detail != "" and not ok else ""))
    if not ok:
        failures.append(name)


def docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def run_once(image: str, entrypoint: str, *args: str) -> subprocess.CompletedProcess:
    return docker("run", "--rm", *platform, "--network", "none", "--read-only",
                  "--entrypoint", entrypoint, image, *args)


def in_container(name: str, code: str) -> subprocess.CompletedProcess:
    return docker("exec", name, "python", "-c", code)


LISTENERS = r"""
import ipaddress, json
found = []
for path, family in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 6)):
    try:
        lines = open(path).read().splitlines()[1:]
    except OSError:
        continue
    for line in lines:
        fields = line.split()
        if fields[3] != "0A":  # LISTEN
            continue
        raw, port = fields[1].rsplit(":", 1)
        data = bytes.fromhex(raw)
        # The kernel prints each 32-bit word in host byte order.
        data = b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))
        address = ipaddress.ip_address(data)
        if family == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        found.append({"address": str(address), "port": int(port, 16),
                      "loopback": address.is_loopback})
print(json.dumps(found))
"""

SOCKET = r"""
import json, os, stat
info = os.stat("%s/openshell.sock")
print(json.dumps({"socket": stat.S_ISSOCK(info.st_mode), "mode": oct(stat.S_IMODE(info.st_mode)),
                  "uid": info.st_uid}))
""" % RUN_DIR

GRPC_READY = r"""
import grpc
channel = grpc.insecure_channel("unix://%s/openshell.sock")
grpc.channel_ready_future(channel).result(timeout=10)
print("ready")
""" % RUN_DIR

HEALTH = r"""
import urllib.request
print(urllib.request.urlopen("http://127.0.0.1:8088/healthz", timeout=2).read().decode())
"""

EVALUATE = r"""
import json, urllib.request
body = json.dumps({"method": "openshell.v1.OpenShell/UpdateConfig", "phase": "validate",
                   "body": {"sandbox": "sb-1", "mergeOperations": [{"addRule": {"ruleName": "r"}}]}})
request = urllib.request.Request("http://127.0.0.1:8088/v1/evaluate", data=body.encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
print(urllib.request.urlopen(request, timeout=10).read().decode())
"""

PLACES = r"""
import json, os, stat
print(json.dumps({path: [os.stat(path).st_uid, os.stat(path).st_gid,
                         oct(stat.S_IMODE(os.stat(path).st_mode))]
                  for path in ("/run/artzain", "/var/lib/artzain")}))
"""

WRITE_OUTSIDE = r"""
import json
refused = {}
for path in ("/opt/artzain/probe", "/tmp/probe", "/probe", "/nonexistent/probe",
             "/var/lib/artzain/probe"):
    try:
        open(path, "w").close()
        refused[path] = False
    except OSError:
        refused[path] = True
print(json.dumps(refused))
"""


def test(image: str, version: str) -> None:
    inspected = docker("image", "inspect", image)
    if inspected.returncode != 0:
        check("the image exists", False, inspected.stderr.strip())
        return
    config = json.loads(inspected.stdout)[0]["Config"]
    check("it runs as uid 10001, by number", config.get("User") == "10001:10001", config.get("User"))
    check("its entrypoint is the sidecar",
          config.get("Entrypoint") == ["artzain", "openshell", "sidecar"], config.get("Entrypoint"))
    check("it declares no port", not config.get("ExposedPorts"), config.get("ExposedPorts"))
    check("it is labelled with its version",
          (config.get("Labels") or {}).get("org.opencontainers.image.version") == version,
          (config.get("Labels") or {}).get("org.opencontainers.image.version"))

    ids = run_once(image, "python", "-c", "import os; print(os.getuid(), os.getgid())")
    check("a process in it is not root", ids.stdout.strip() == "10001 10001",
          ids.stdout.strip() or ids.stderr.strip())
    installed = run_once(image, "python", "-c", "import artzain; print(artzain.__version__)")
    check(f"it holds artzain {version}", installed.stdout.strip() == version,
          installed.stdout.strip() or installed.stderr.strip())
    places = run_once(image, "python", "-c", PLACES)
    check("its two writable places are its own and nobody else's",
          places.returncode == 0 and json.loads(places.stdout) == {
              "/run/artzain": [10001, 10001, "0o700"],
              "/var/lib/artzain": [10001, 10001, "0o700"]},
          places.stdout.strip() or places.stderr.strip())
    for python in ("python", "/usr/local/bin/python3"):
        pip = run_once(image, python, "-m", "pip", "--version")
        check(f"{python} has no pip", pip.returncode != 0, pip.stdout.strip())

    name = "artzain-sidecar-image-test-" + uuid.uuid4().hex[:12]
    started = docker(
        "run", "-d", "--name", name, *platform, "--network", "none", "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--tmpfs", f"{RUN_DIR}:rw,noexec,nosuid,uid=10001,gid=10001,mode=0700",
        "-e", f"OPENSHELL_SIDECAR_GRPC=unix://{RUN_DIR}/openshell.sock",
        "-e", f"OPENSHELL_SIDECAR_STATE={RUN_DIR}/state.json",
        "-e", f"OPENSHELL_SIDECAR_JOURNAL={RUN_DIR}/journal.json",
        "-e", "OPENSHELL_GATEWAY_ID=gw-image-test",
        "-e", "ARTZAIN_DECISION_URL=http://127.0.0.1:9",
        "-e", f"COGNEXUS_API_KEY={TEST_KEY}",
        image)
    if started.returncode != 0:
        check("the container starts", False, started.stderr.strip())
        return
    try:
        healthy = None
        until = time.monotonic() + 60
        while time.monotonic() < until:
            healthy = in_container(name, HEALTH)
            if healthy.returncode == 0:
                break
            state = docker("inspect", "-f", "{{.State.Running}}", name).stdout.strip()
            if state != "true":
                break
            time.sleep(1)
        check("the sidecar is healthy with no network and a read-only root filesystem",
              healthy is not None and healthy.returncode == 0 and '"ok": true' in healthy.stdout,
              docker("logs", "--tail", "40", name).stderr.strip())

        listeners = in_container(name, LISTENERS)
        found = json.loads(listeners.stdout) if listeners.returncode == 0 else None
        check("its only TCP listener is 127.0.0.1:8088",
              found == [{"address": "127.0.0.1", "port": 8088, "loopback": True}],
              found if found is not None else listeners.stderr.strip())

        socket = in_container(name, SOCKET)
        check("the gateway's socket is there, and its owner's alone",
              socket.returncode == 0 and json.loads(socket.stdout) == {
                  "socket": True, "mode": "0o600", "uid": 10001},
              socket.stdout.strip() or socket.stderr.strip())
        ready = in_container(name, GRPC_READY)
        check("the socket answers gRPC", ready.stdout.strip() == "ready", ready.stderr.strip()[-400:])

        outside = in_container(name, WRITE_OUTSIDE)
        refused = json.loads(outside.stdout) if outside.returncode == 0 else {}
        check("nothing outside its mount can be written",
              bool(refused) and all(refused.values()), refused or outside.stderr.strip())

        evaluated = in_container(name, EVALUATE)
        answer = json.loads(evaluated.stdout) if evaluated.returncode == 0 else {}
        check("a governed write is denied when the engine cannot be reached",
              answer.get("allowed") is False and answer.get("status_code") == 503,
              answer or evaluated.stderr.strip())

        stopping = time.monotonic()
        docker("stop", "--time", "20", name)
        took = time.monotonic() - stopping
        state = json.loads(docker("inspect", "-f", "{{json .State}}", name).stdout or "{}")
        check("it stops when asked to", state.get("ExitCode") == 0 and took < 15,
              {"exit": state.get("ExitCode"), "seconds": round(took, 1)})
        logs = docker("logs", name)
        text = logs.stdout + logs.stderr
        check("the key is not in its log", TEST_KEY not in text)
        check("it logged how it reaches the engine", "engine connection:" in text, text[-400:])
    finally:
        docker("rm", "-f", name)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--version", required=True, help="the artzain version the image must hold")
    ap.add_argument("--platform", help="run the image for this platform, e.g. linux/arm64")
    args = ap.parse_args()
    if args.platform:
        platform.extend(["--platform", args.platform])
    test(args.image, args.version)
    if failures:
        print(f"\n{len(failures)} check(s) failed: " + "; ".join(failures), file=sys.stderr)
        return 1
    print("\nthe image runs as its Dockerfile says")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
