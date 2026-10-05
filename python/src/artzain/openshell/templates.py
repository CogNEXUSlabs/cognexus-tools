"""What ``artzain connect openshell up`` writes, for every option it can be
given, and the invariants each rendering holds (Option C plan, S4.2 and §6).

``up`` renders the gateway's files on the operator's host. This renders the
same files, with the same functions, for a stand-in host, so that CI can see
every combination of the approved configuration and the ``gateway.toml`` an
operator may already have:

* the SDK's tests hold each rendering to a golden file;
* :func:`invariants` checks the plan's §6 on each one: the sidecar is reached
  on a Unix socket and serves HTTP on loopback only; the deciding
  registration fails closed and the observing one binds after the commit;
  the timeouts and the telemetry choice are the approved ones; the
  credential is in the sidecar's private settings and nowhere else; nothing
  sets who the sidecar decides as; the units keep the sidecar's files
  private and make the gateway wait for it; NVIDIA is named only as "Works
  with NVIDIA OpenShell"; and taking the block out gives the file back byte
  for byte;
* the conformance run puts each distinct ``gateway.toml`` through the real
  gateway's ``config preflight`` (S1.4 f).

``python -m artzain.openshell.templates write DIR`` writes the golden files;
``gateway-tomls DIR`` writes each distinct ``gateway.toml``, for preflight.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from artzain.openshell import connect, registration
from artzain.openshell.interceptor import PHASE_POST, PINNED_OPENSHELL

#: The stand-in host the renderings are for.
HOME = "/home/operator"
UID = 1000
PYTHON = f"{HOME}/.local/share/uv/tools/artzain/bin/python"
DECISION_URL = "https://engine.example"
GATEWAY_ID = "gw_" + "0" * 26
CREDENTIAL = connect.CREDENTIAL_PREFIX + "stand-in-credential-not-a-real-key"
PROXY = "http://proxy.example:3128"
CA_BUNDLE = "/etc/ssl/certs/corporate-ca.pem"
ALLOWED_NVIDIA = "Works with NVIDIA OpenShell"

#: The ``gateway.toml`` an operator may already have: none (a package install
#: on its defaults), a bare one, and one with settings, the gateway's own key
#: and an interceptor of the operator's.
BASES: Dict[str, Optional[str]] = {
    "none": None,
    "minimal": "[openshell]\nversion = 2\n",
    "operator": f"""\
[openshell]
version = 2

[openshell.gateway]
bind_address = "127.0.0.1:17670"
log_level = "info"

[openshell.gateway.gateway_jwt]
signing_key_path = "{HOME}/.config/openshell/jwt/signing.pem"
public_key_path = "{HOME}/.config/openshell/jwt/public.pem"
kid_path = "{HOME}/.config/openshell/jwt/kid"
gateway_id = "laptop"

[[openshell.gateway.interceptors]]
name = "audit"
grpc_endpoint = "unix:///run/user/{UID}/audit.sock"
order = 5
binding_policy = "allowlist"
failure_policy = "fail_open"
timeout = "500ms"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["post_commit"]
""",
}

#: ``(interceptor_timeout_ms, decide_timeout_ms)``: the smallest a
#: configuration can carry (the decide timeout is 50 ms at least, and below
#: the interceptor's), the default, and the largest.
TIMEOUTS = ((51, 50), (registration.TIMEOUT_MS_DEFAULT, 1200),
            (registration.TIMEOUT_MS_MAX, 30_000))


@dataclass(frozen=True)
class Combination:
    """One approved configuration on one starting ``gateway.toml``. The proxy
    and CA bundle ride on the telemetry-on half, so each value of each is
    rendered."""

    interceptor_timeout_ms: int
    decide_timeout_ms: int
    base: str
    telemetry: bool

    @property
    def proxy(self) -> bool:
        return self.telemetry

    @property
    def name(self) -> str:
        return (f"t{self.interceptor_timeout_ms}-{self.base}-telemetry-"
                f"{'on' if self.telemetry else 'off'}")

    @property
    def config(self) -> Dict[str, Any]:
        """The configuration as the engine issues it."""
        return {"kind": connect.CONFIG_KIND, "version": connect.CONFIG_VERSION,
                "decision_url": DECISION_URL, "openshell_version": PINNED_OPENSHELL.lstrip("v"),
                "interceptor_timeout_ms": self.interceptor_timeout_ms,
                "decide_timeout_ms": self.decide_timeout_ms, "telemetry": self.telemetry}

    @property
    def parsed(self) -> connect.ConnectConfig:
        return connect.parse_config(self.config)

    @property
    def base_text(self) -> Optional[str]:
        return BASES[self.base]


COMBINATIONS = tuple(Combination(interceptor, decide, base, telemetry)
                     for interceptor, decide in TIMEOUTS
                     for base in BASES
                     for telemetry in (False, True))


def stand_in_host() -> connect.Host:
    return connect.Host(
        environ={"HOME": HOME, "XDG_RUNTIME_DIR": f"/run/user/{UID}", "PATH": "/usr/bin"},
        root="/nonexistent-root", which=lambda name: f"/usr/bin/{name}",
        executable=PYTHON, uid=UID, platform="linux")


def render_for(host: connect.Host, config: connect.ConnectConfig, *, toml_text: str,
               gateway_id: str, credential: str, port: int, proxy: str,
               ca_bundle: str) -> Dict[str, str]:
    """What ``up`` writes on *host*, by path under the home folder, in the
    order it writes them. Raises :class:`connect.ConnectError` where ``up``
    would."""
    paths = connect.layout(host)

    def under_home(path: Path) -> str:
        return path.relative_to(host.home).as_posix()

    text = connect.registration_text(paths, config, toml_text)
    return {
        under_home(paths.gateway_toml):
            connect.add_block(toml_text.encode("utf-8"), text).decode("utf-8"),
        under_home(paths.gateway_env):
            connect.add_block(b"", connect.telemetry_line(config)).decode("utf-8"),
        under_home(paths.sidecar_env): connect.sidecar_environment(
            host, paths, gateway_id, credential, config,
            registration_digest=registration.digest(connect.sidecar_registration(paths, config)),
            port=port, proxy=proxy, ca_bundle=ca_bundle,
            jwt=connect._jwt_settings(toml_text, host)),
        under_home(paths.sidecar_unit): connect.sidecar_unit(host, paths),
        under_home(paths.dropin): connect.gateway_dropin(),
    }


def render(combo: Combination) -> Dict[str, str]:
    return render_for(stand_in_host(), combo.parsed, toml_text=combo.base_text or "",
                      gateway_id=GATEWAY_ID, credential=CREDENTIAL, port=connect.DEFAULT_PORT,
                      proxy=PROXY if combo.proxy else "",
                      ca_bundle=CA_BUNDLE if combo.proxy else "")


def as_text(files: Mapping[str, str]) -> str:
    """The files as one text: a golden file."""
    return "".join(f"==> {name} <==\n{text}" + ("" if text.endswith("\n") else "\n")
                   for name, text in files.items())


def gateway_tomls() -> Dict[str, str]:
    """Each distinct ``gateway.toml`` the combinations render: one per
    timeout and starting file (telemetry is in ``gateway.env``)."""
    out: Dict[str, str] = {}
    for combo in COMBINATIONS:
        name = f"t{combo.interceptor_timeout_ms}-{combo.base}"
        text = next(iter(render(combo).values()))
        if out.setdefault(name, text) != text:
            raise ValueError(f"{name} renders two gateway.toml files")
    return out


# ---------------------------------------------------------------------------
# The invariants
# ---------------------------------------------------------------------------


def _env(text: str) -> Dict[str, str]:
    values = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, _, value = line.partition("=")
            values[name] = value.strip('"')
    return values


def invariants(files: Mapping[str, str], base_text: Optional[str], *,
               config: connect.ConnectConfig, credential: str) -> List[str]:
    """What is wrong with a rendering, against the plan's §6 and the approved
    *config*; empty when it holds. *base_text* is the ``gateway.toml`` the
    rendering started from (None: there was none)."""
    import tomllib

    by_end = {}
    found: List[str] = []
    for wanted in ("openshell/gateway.toml", "openshell/gateway.env",
                   "artzain/openshell/sidecar.env", f"systemd/user/{connect.SIDECAR_UNIT}",
                   f"systemd/user/{connect.GATEWAY_UNIT}.d/{connect.DROPIN}"):
        name = next((n for n in files if n.endswith(wanted)), None)
        if name is None:
            found.append(f"{wanted} is not written")
        by_end[wanted] = files.get(name, "") if name else ""
    toml_text = by_end["openshell/gateway.toml"]
    gateway_env = by_end["openshell/gateway.env"]
    sidecar = _env(by_end["artzain/openshell/sidecar.env"])
    unit = by_end[f"systemd/user/{connect.SIDECAR_UNIT}"]
    dropin = by_end[f"systemd/user/{connect.GATEWAY_UNIT}.d/{connect.DROPIN}"]

    # The registrations: on the sidecar's socket, fail closed where they decide.
    try:
        doc = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError as exc:
        return found + [f"gateway.toml is not TOML ({exc})"]
    openshell = doc.get("openshell") if isinstance(doc.get("openshell"), dict) else {}
    if openshell.get("version") != 2:
        found.append("gateway.toml must say [openshell] version = 2")
    entries = (openshell.get("gateway") or {}).get("interceptors") or []
    socket = sidecar.get("OPENSHELL_SIDECAR_GRPC", "")
    for name in registration.NAMES:
        mine = [e for e in entries if isinstance(e, dict) and e.get("name") == name]
        if len(mine) != 1:
            found.append(f"gateway.toml must register {name} exactly once")
            continue
        entry = mine[0]
        endpoint = str(entry.get("grpc_endpoint") or "")
        if not endpoint.startswith("unix:///"):
            found.append(f"{name} must reach the sidecar on a Unix socket (outbound only)")
        elif endpoint != socket:
            found.append(f"{name} does not call the sidecar's socket ({socket})")
        if entry.get("timeout") != f"{config.interceptor_timeout_ms}ms":
            found.append(f"{name}'s timeout is not the approved "
                         f"{config.interceptor_timeout_ms}ms")
        if name == registration.DECIDING and entry.get("failure_policy") != "fail_closed":
            found.append(f"{name} must be the registration that fails closed")
        if name == registration.OBSERVING and any(
                set(binding.get("phases") or []) - {PHASE_POST}
                for binding in entry.get("bindings") or []):
            found.append(f"{name} may only bind after the commit ({PHASE_POST})")
    if connect.strip_block(toml_text.encode("utf-8")) != (base_text or "").encode("utf-8"):
        found.append("gateway.toml would not come back byte for byte when the block is "
                     "taken out")

    # The gateway's telemetry choice.
    if connect.strip_block(gateway_env.encode("utf-8")) != b"" or (
            connect.telemetry_line(config) not in gateway_env.splitlines()):
        found.append("gateway.env does not carry the approved telemetry choice, as one "
                     "removable block")

    # The sidecar: a deny before the gateway gives up, HTTP on loopback, and
    # the credential is who it decides as.
    # The approved one is below the interceptor's: parse_config refuses others.
    if sidecar.get("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS") != str(config.decide_timeout_ms):
        found.append("the sidecar's decide timeout must be the approved one, below the "
                     "interceptor's")
    if sidecar.get("OPENSHELL_SIDECAR_HOST") != "127.0.0.1":
        found.append("the sidecar's HTTP port must be on loopback (127.0.0.1)")
    if sidecar.get("COGNEXUS_API_KEY") != credential:
        found.append("the sidecar's settings do not hold the gateway's credential")
    if any("AGENT_DID" in name or "AGENT_ID" in name for name in sidecar):
        found.append("the sidecar decides as its credential's gateway: nothing may set who "
                     "it decides as")
    for name, text in files.items():
        if not name.endswith("artzain/openshell/sidecar.env") and credential in text:
            found.append(f"the credential is in {name}: it belongs only in the sidecar's "
                         "private settings")

    # The units: private files, and a gateway that waits for its sidecar.
    for line in ("UMask=0077", "NoNewPrivileges=yes", "Type=notify"):
        if line not in unit.splitlines():
            found.append(f"the sidecar's unit must say {line}")
    if not any(line.startswith("EnvironmentFile=") and line.endswith(
            "/artzain/openshell/sidecar.env") for line in unit.splitlines()):
        found.append("the sidecar's unit must read its settings from sidecar.env")
    for line in (f"Requires={connect.SIDECAR_UNIT}", f"After={connect.SIDECAR_UNIT}"):
        if line not in dropin.splitlines():
            found.append(f"the gateway's drop-in must say {line}")

    # Shipped strings.
    for name, text in files.items():
        if "NVIDIA" in text.replace(ALLOWED_NVIDIA, ""):
            found.append(f"{name} names NVIDIA other than as \"{ALLOWED_NVIDIA}\"")
    return found


def write(directory: Path, combos: Sequence[Combination] = COMBINATIONS) -> List[Path]:
    """Write each combination's golden file into *directory*."""
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for combo in combos:
        path = directory / f"{combo.name}.txt"
        path.write_bytes(as_text(render(combo)).encode("utf-8"))
        written.append(path)
    return written


def write_gateway_tomls(directory: Path) -> List[Path]:
    """Write each distinct ``gateway.toml`` into *directory*, for the
    gateway's ``config preflight``."""
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in gateway_tomls().items():
        path = directory / f"{name}.toml"
        path.write_bytes(text.encode("utf-8"))
        written.append(path)
    return written


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    commands = {"write": write, "gateway-tomls": write_gateway_tomls}
    if len(args) != 2 or args[0] not in commands:
        print("usage: python -m artzain.openshell.templates {write|gateway-tomls} DIRECTORY",
              file=sys.stderr)
        return 2
    for path in commands[args[0]](Path(args[1])):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
