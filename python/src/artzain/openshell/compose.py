"""The Compose gateway shape of ``artzain connect openshell``.

NVIDIA's ``deploy/docker/docker-compose.yml`` runs the gateway as a Compose
service from ``ghcr.io/nvidia/openshell/gateway``, as root, with its
``gateway.toml`` bind-mounted read-only from the project folder. ``up``
binds such a gateway without editing the operator's compose files:

* the sidecar runs as a second service of the same project, from the
  ArtzAIn sidecar image of this artzain release. cosign (pinned by SHA-256,
  as ``upgrade`` pins it) checks the image's signature against the mirror's
  ``sidecar-image.yml`` at the ``sidecar-v<version>`` tag, and the image is
  named by the digest it verified;
* the interceptor's Unix socket is on a named volume both containers mount
  at ``/run/artzain``, and the gateway starts only once the sidecar is
  healthy;
* all of that is in a file of ``up``'s own (:data:`FILE`, beside the
  sidecar's settings), which a marked block in the project's ``.env`` adds
  to ``COMPOSE_FILE``. ``docker compose up -d`` in the project folder then
  keeps the gateway bound, and ``remove`` takes the block out.

The sidecar runs on the host's network, as the native sidecar runs on the
host: its routes are on this host's loopback only, and it reaches the engine
the way this host does. It runs as uid 10001 on a read-only root
filesystem, with no capabilities.

Nothing here decides or logs a credential; :mod:`artzain.openshell.connect`
runs the steps. The host is duck-typed (``run``, ``uid``, ``sleep``,
``clock``): the same ``Host`` connect uses.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: NVIDIA's gateway image, under any tag or digest.
GATEWAY_IMAGE = "ghcr.io/nvidia/openshell/gateway"
#: The sidecar image the mirror publishes for each artzain release, and who
#: signs it: the mirror's sidecar-image.yml at that release's tag.
SIDECAR_IMAGE = "ghcr.io/cognexuslabs/artzain-openshell-sidecar"
ISSUER = "https://token.actions.githubusercontent.com"
SIGNER = ("https://github.com/CogNEXUSlabs/cognexus-tools/.github/workflows/"
          "sidecar-image.yml@refs/tags/sidecar-v{version}")

#: The sidecar's service, and the project's volumes it brings.
SERVICE = "artzain-sidecar"
SOCKET_VOLUME = "artzain-socket"
STATE_VOLUME = "artzain-state"
#: Where things are inside the containers.
SOCKET = "/run/artzain/openshell.sock"
STATE = "/var/lib/artzain"
#: The folder that holds gateway.toml, read-only. Its folder rather than the
#: file: a bind of one file holds on to the file as it was when the
#: container started, and a file replaced by a rename (as up writes it, and
#: as most editors save) would go unseen by the sidecar's heartbeat.
GATEWAY_FOLDER = "/etc/artzain/gateway"
JWT_KEY = "/etc/artzain/gateway-jwt.pem"
#: Where preflight reads the candidate file in a throwaway gateway container.
CANDIDATE = "/tmp/artzain-candidate.toml"
#: The sidecar image's user, which owns the socket (mode 0600).
SIDECAR_UID = 10001

#: up's compose file, kept beside the sidecar's settings, and where the
#: project's .env is kept while it is bound.
FILE = "compose.yml"
ENV_BACKUP = "compose.env.before"

_LABEL = "com.docker.compose."
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
#: A sidecar image named by content: ``name@sha256:<hex>``, or a local
#: image's id, ``sha256:<hex>``.
_PINNED = re.compile(r"(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SERVICE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")
_HASH = re.compile(r"[0-9a-f]{64}")
#: What a path or value written into a compose file, a docker --mount or
#: COMPOSE_FILE cannot hold here: Compose interpolates "$", COMPOSE_FILE
#: splits on ":", --mount on ",".
_UNSAFE = re.compile(r"[\x00-\x1f\x7f\"'\\$%`:,]")
_UNSAFE_VALUE = re.compile(r"[\x00-\x1f\x7f\"'\\$`]")
#: The users a container runs as root under.
_ROOT = ("0", "root", "0:0", "root:root", "0:root", "root:0")


def _refused(message: str) -> Exception:
    from artzain.openshell.connect import ConnectError

    return ConnectError(message)


def _said(done: Any) -> str:
    text = re.sub(r"\x1b\[[0-9;]*m", "", (done.stderr or "") + " " + (done.stdout or ""))
    return " ".join(text.split())[-300:]


@dataclass(frozen=True)
class Mount:
    kind: str           # "bind" or "volume"
    source: str         # the host path of a bind, the name of a volume
    destination: str


@dataclass(frozen=True)
class Project:
    """A Compose project's OpenShell gateway, as Docker says it runs."""

    name: str
    directory: Path
    #: The operator's compose files, as the project was last brought up with,
    #: without :data:`FILE`.
    files: Tuple[str, ...]
    service: str
    container: str
    image: str
    gateway_toml: Path
    user: str
    mounts: Tuple[Mount, ...]
    config_hash: str
    status: str

    def facts(self) -> Dict[str, Any]:
        """What the record keeps: enough for ``remove`` once the gateway is gone."""
        return {"project": self.name, "directory": self.directory.as_posix(),
                "files": list(self.files), "service": self.service,
                "gateway_toml": self.gateway_toml.as_posix()}


def _labels(container: Mapping[str, Any]) -> Dict[str, str]:
    labels = (container.get("Config") or {}).get("Labels") or {}
    return {k: v for k, v in labels.items() if isinstance(v, str)}


def _inspect(host: Any, *filters: str, strict: bool = False) -> List[Dict[str, Any]]:
    """``docker inspect`` of every container (running or not) the filters
    match. Empty when docker cannot say, or, when *strict*, raises."""
    argv = ["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}"]
    for value in filters:
        argv += ["--filter", value]
    done = host.run(*argv, timeout=30)
    if done.returncode != 0 and strict:
        raise _refused("docker is on PATH, but this user cannot use it, so a gateway under "
                       "Compose cannot be looked for (run this as a user in the docker group, "
                       f"with Docker running): {_said(done)}")
    ids = [line.strip() for line in (done.stdout or "").splitlines() if line.strip()]
    if done.returncode != 0 or not ids:
        return []
    done = host.run("docker", "inspect", *ids, timeout=60)
    try:
        found = json.loads(done.stdout or "[]") if done.returncode == 0 else []
    except ValueError:
        found = []
    return [c for c in found if isinstance(c, dict)] if isinstance(found, list) else []


def _mounts(container: Mapping[str, Any]) -> Tuple[Mount, ...]:
    out = []
    for m in container.get("Mounts") or []:
        if isinstance(m, dict) and isinstance(m.get("Destination"), str):
            kind = str(m.get("Type") or "")
            source = str(m.get("Name") if kind == "volume" else m.get("Source") or "")
            out.append(Mount(kind, source, m["Destination"]))
    return tuple(out)


def _env(container: Mapping[str, Any]) -> Dict[str, str]:
    pairs = (container.get("Config") or {}).get("Env") or []
    return dict(item.split("=", 1) for item in pairs if isinstance(item, str) and "=" in item)


def _status(container: Optional[Mapping[str, Any]]) -> str:
    """``running``, ``running (healthy)``, ``restarting``, ``exited``... or
    ``missing``."""
    if not container:
        return "missing"
    state = container.get("State") or {}
    status = str(state.get("Status") or "unknown")
    health = (state.get("Health") or {}).get("Status")
    return f"{status} ({health})" if health and status == "running" else status


def _is_gateway(container: Mapping[str, Any]) -> bool:
    image = str((container.get("Config") or {}).get("Image") or "")
    return ((image == GATEWAY_IMAGE or image.startswith((GATEWAY_IMAGE + ":", GATEWAY_IMAGE + "@")))
            and bool(_env(container).get("OPENSHELL_GATEWAY_CONFIG")))


def find(host: Any, ours: Path) -> Optional[Project]:
    """The Compose-run OpenShell gateway on this host, or None. *ours* is
    :data:`FILE`'s path, which a bound project lists among its files."""
    gateways = [c for c in _inspect(host, "label=" + _LABEL + "project", strict=True)
                if _is_gateway(c)]
    if not gateways:
        return None
    if len(gateways) > 1:
        names = sorted({_labels(c).get(_LABEL + "project", "?") for c in gateways})
        raise _refused(f"this host runs {len(gateways)} OpenShell gateways under Compose "
                       f"(projects {', '.join(names)}): this release binds one per host")
    container = gateways[0]
    labels = _labels(container)
    name = labels.get(_LABEL + "project", "")
    directory = labels.get(_LABEL + "project.working_dir", "")
    service = labels.get(_LABEL + "service", "")
    files = tuple(f for f in labels.get(_LABEL + "project.config_files", "").split(",")
                  if f and PurePosixPath(f) != PurePosixPath(ours.as_posix()))
    if not (name and directory and files and _SERVICE_NAME.fullmatch(service)):
        raise _refused("the OpenShell gateway's container does not say which Compose project "
                       "and files it was brought up from")
    config = _env(container)["OPENSHELL_GATEWAY_CONFIG"]
    mounts = _mounts(container)
    mount = next((m for m in mounts if m.destination == config), None)
    if mount is None or mount.kind != "bind":
        raise _refused(f"the gateway reads {config}, which is not a file bind-mounted from "
                       "this host: up adds the registration to that file")
    return Project(
        name=name, directory=Path(directory), files=files, service=service,
        container=str(container.get("Id") or ""), image=str(container.get("Image") or ""),
        gateway_toml=Path(mount.source),
        user=str((container.get("Config") or {}).get("User") or ""),
        mounts=mounts, config_hash=labels.get(_LABEL + "config-hash", ""),
        status=_status(container))


def recorded(facts: Mapping[str, Any]) -> Project:
    """The project as the connect record keeps it: what ``remove`` needs,
    even once the gateway's container is gone."""
    files = facts.get("files")
    if not (isinstance(facts.get("project"), str) and facts["project"]
            and isinstance(facts.get("directory"), str) and facts["directory"]
            and isinstance(files, list) and files and all(isinstance(f, str) for f in files)
            and isinstance(facts.get("service"), str)
            and _SERVICE_NAME.fullmatch(facts["service"])
            and isinstance(facts.get("gateway_toml"), str) and facts["gateway_toml"]):
        raise _refused("the connect record does not say which Compose project the gateway "
                       "is in: move it aside, and take the sidecar out by hand (manual "
                       "chapter 17)")
    return Project(name=facts["project"], directory=Path(facts["directory"]),
                   files=tuple(files), service=facts["service"], container="", image="",
                   gateway_toml=Path(facts["gateway_toml"]), user="", mounts=(),
                   config_hash="", status="")


def check(project: Project, ours: Path) -> None:
    """Raise unless ``up`` can bind *project* from this host."""
    if project.user not in _ROOT:
        raise _refused(f"the gateway's container runs as {project.user or 'its image user'}, "
                       f"not root: it could not open the sidecar's socket (uid {SIDECAR_UID}, "
                       "mode 0600). NVIDIA's compose file runs it as user \"0\"")
    if not project.directory.is_dir():
        raise _refused(f"the project's folder {project.directory} is not on this host: run "
                       "this on the host that runs the gateway's containers")
    for path in (*project.files, project.gateway_toml.as_posix(), ours.as_posix()):
        if _UNSAFE.search(path):
            raise _refused(f"{path}: up writes this path into a compose file or "
                           "COMPOSE_FILE, which cannot carry it")
        if path != ours.as_posix() and not Path(path).is_file():
            raise _refused(f"{path} is not a file on this host")
    # The sidecar's user reads it, for the heartbeat's registration check.
    if not project.gateway_toml.stat().st_mode & 0o004:
        raise _refused(f"{project.gateway_toml} is not readable by other users: the sidecar's "
                       f"container (uid {SIDECAR_UID}) reads it, read-only, to report whether "
                       "the registration is still there. chmod o+r it, then run this again")


def toml_inside(gateway_toml: Path) -> str:
    """*gateway_toml* where the sidecar's container reads it."""
    return f"{GATEWAY_FOLDER}/{gateway_toml.name}"


def version(host: Any, project: Project) -> str:
    """The OpenShell release of the gateway's image."""
    done = host.run("docker", "run", "--rm", "--network", "none", project.image, "--version",
                    timeout=120)
    found = _VERSION.search((done.stdout or "") + " " + (done.stderr or ""))
    if done.returncode != 0 or not found:
        raise _refused("the gateway's image did not say its OpenShell release "
                       f"(openshell-gateway --version): {_said(done)}")
    return found.group(0)


def jwt(project: Project, toml_text: str) -> Optional[Tuple[str, str]]:
    """``(host path of the public key, gateway id)`` of the gateway's
    ``gateway_jwt``, or None when it signs nothing. The key is read where
    the gateway's container mounts it from."""
    import tomllib

    try:
        signing = (tomllib.loads(toml_text).get("openshell", {}).get("gateway", {})
                   .get("gateway_jwt"))
    except tomllib.TOMLDecodeError:
        return None
    if not isinstance(signing, dict):
        return None
    key, gateway = signing.get("public_key_path"), signing.get("gateway_id")
    if not (isinstance(key, str) and isinstance(gateway, str) and key and gateway):
        return None
    inside = PurePosixPath(key)
    for mount in sorted(project.mounts, key=lambda m: len(m.destination), reverse=True):
        where = PurePosixPath(mount.destination)
        if mount.kind == "bind" and (inside == where or where in inside.parents):
            source = PurePosixPath(mount.source) / inside.relative_to(where)
            if _UNSAFE.search(source.as_posix()) or _UNSAFE.search(gateway):
                break
            return source.as_posix(), gateway
    raise _refused(f"gateway.toml names the gateway_jwt public key {key}, which the gateway's "
                   "container does not mount from a folder of this host: the sidecar checks "
                   "the gateway's calls with that key")


def preflight(host: Any, project: Project, trial: Path) -> Any:
    """The gateway's own ``config preflight`` on *trial*, in a throwaway
    container of its image, with no network."""
    return host.run("docker", "run", "--rm", "--network", "none", "--user", str(host.uid),
                    "--mount", f"type=bind,source={trial.as_posix()},target={CANDIDATE},readonly",
                    project.image, "config", "preflight", "--path", CANDIDATE, timeout=120)


def _compose(project: Project, ours: Optional[Path]) -> List[str]:
    argv = ["docker", "compose", "-p", project.name, "--project-directory",
            project.directory.as_posix()]
    for path in project.files:
        argv += ["-f", path]
    if ours is not None:
        argv += ["-f", ours.as_posix()]
    return argv


def config_hash(host: Any, project: Project, ours: Optional[Path]) -> str:
    """The configuration hash Compose gives the gateway's service from the
    operator's files, and *ours* when given (empty when it cannot say)."""
    done = host.run(*_compose(project, ours), "config", f"--hash={project.service}", timeout=60)
    return _hash_said(done, project.service)


def operator_hash(host: Any, project: Project) -> str:
    """The hash the gateway's service gets from ``docker compose`` in the
    project folder with no ``-f``, as the operator runs it: the files
    ``COMPOSE_FILE`` names in its ``.env``, or the default ones."""
    done = host.run("docker", "compose", "--project-directory", project.directory.as_posix(),
                    "config", f"--hash={project.service}", timeout=60)
    return _hash_said(done, project.service)


def _hash_said(done: Any, service: str) -> str:
    if done.returncode != 0:
        return ""
    for line in (done.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == service and _HASH.fullmatch(parts[1]):
            return parts[1]
    return ""


def up(host: Any, project: Project, ours: Optional[Path], service: str, *,
       recreate: bool = False, start: bool = True) -> Any:
    """``docker compose up -d --no-deps`` of one service, from the operator's
    files and *ours* when given; with *start* false, created and left
    stopped (``--no-start``)."""
    argv = _compose(project, ours) + ["up", "-d" if start else "--no-start", "--no-deps"]
    if recreate:
        argv.append("--force-recreate")
    return host.run(*argv, service, timeout=600)


def containers(host: Any, project: str) -> Dict[str, Dict[str, Any]]:
    """The project's containers by service: the running one when there are
    several."""
    out: Dict[str, Dict[str, Any]] = {}
    for c in _inspect(host, f"label={_LABEL}project={project}"):
        service = _labels(c).get(_LABEL + "service", "")
        running = ((c.get("State") or {}).get("Status") == "running")
        if service and (service not in out or running):
            out[service] = c
    return out


def status(host: Any, project: str, service: str) -> str:
    return _status(containers(host, project).get(service))


def stays_up(host: Any, project: str, service: str, *, seconds: float = 30.0) -> bool:
    """The gateway's container is running, and is still running, not
    restarted, a few seconds later: a gateway that cannot reach its
    interceptor exits at start, and Docker restarts it."""
    def look() -> Tuple[str, str, int]:
        c = containers(host, project).get(service) or {}
        return (str(c.get("Id") or ""), str((c.get("State") or {}).get("Status") or ""),
                int(c.get("RestartCount") or 0))

    until = host.clock() + seconds
    first = look()
    while first[1] != "running":
        if host.clock() >= until:
            return False
        host.sleep(0.5)
        first = look()
    host.sleep(6)
    return look() == first


def restart(host: Any, project: Project, service: str) -> Any:
    return host.run(*_compose(project, None), "restart", service, timeout=300)


def remove_sidecar(host: Any, project: str) -> List[str]:
    """Remove the sidecar's containers and the project's volumes up made.
    Returns what went."""
    gone = []
    ids = [str(c.get("Id")) for s, c in containers(host, project).items() if s == SERVICE]
    for container in ids:
        if host.run("docker", "rm", "--force", container, timeout=120).returncode == 0:
            gone.append("container")
    for volume in (SOCKET_VOLUME, STATE_VOLUME):
        done = host.run("docker", "volume", "ls", "--quiet", "--filter",
                        f"label={_LABEL}project={project}", "--filter",
                        f"label={_LABEL}volume={volume}", timeout=30)
        for name in (done.stdout or "").split():
            if host.run("docker", "volume", "rm", name, timeout=60).returncode == 0:
                gone.append(volume)
    return gone


_SOCKET_PROBE = (
    "import json, os, stat\n"
    "def look(p):\n"
    "    try:\n"
    "        s = os.stat(p)\n"
    "    except OSError:\n"
    "        return None\n"
    "    return [stat.S_ISSOCK(s.st_mode), stat.S_IMODE(s.st_mode), s.st_uid]\n"
    f"print(json.dumps({{'socket': look({SOCKET!r}), 'folder': look({str(PurePosixPath(SOCKET).parent)!r})}}))\n"
)


def socket(host: Any, container: str) -> Optional[Dict[str, Any]]:
    """The socket and its folder as the sidecar's container sees them:
    ``{"socket": [is a socket, mode, uid] or None, "folder": ...}``, or None
    when the container does not say."""
    done = host.run("docker", "exec", container, "python", "-c", _SOCKET_PROBE, timeout=30)
    try:
        answer = json.loads(done.stdout or "") if done.returncode == 0 else None
    except ValueError:
        return None
    return answer if isinstance(answer, dict) else None


def mounts_socket(container: Optional[Mapping[str, Any]]) -> bool:
    """Whether a container mounts the socket's volume where the sidecar
    serves it."""
    folder = str(PurePosixPath(SOCKET).parent)
    return any(m.kind == "volume" and m.source.endswith("_" + SOCKET_VOLUME)
               and m.destination == folder for m in _mounts(container or {}))


# ---------------------------------------------------------------------------
# The sidecar's image
# ---------------------------------------------------------------------------


def pinned(reference: str) -> bool:
    """Whether *reference* names an image by its content."""
    return bool(_PINNED.fullmatch(reference))


def verify_image(host: Any, cosign: Path, release: str) -> str:
    """The sidecar image of artzain *release*, by the digest cosign verified
    as signed by the mirror's sidecar-image.yml at ``sidecar-v<release>``."""
    tag = f"{SIDECAR_IMAGE}:{release}"
    done = host.run(str(cosign), "verify", tag, "--certificate-oidc-issuer", ISSUER,
                    "--certificate-identity", SIGNER.format(version=release), timeout=300)
    if done.returncode != 0:
        raise _refused(f"the sidecar image {tag} does not verify as signed by "
                       f"sidecar-image.yml at sidecar-v{release} (is that image published "
                       f"yet?): {_said(done)}")
    try:
        said = json.loads(done.stdout or "")
    except ValueError:
        said = None
    digests = set()
    for item in said if isinstance(said, list) else []:
        critical = item.get("critical") if isinstance(item, dict) else None
        critical = critical if isinstance(critical, dict) else {}
        named = (critical.get("identity") or {}).get("docker-reference")
        digest = (critical.get("image") or {}).get("docker-manifest-digest")
        if named != SIDECAR_IMAGE or not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            digests.add(None)
        else:
            digests.add(digest)
    if len(digests) != 1 or None in digests:
        raise _refused(f"cosign verified {tag}, but did not name one digest of "
                       f"{SIDECAR_IMAGE} for it: not using it")
    return f"{SIDECAR_IMAGE}@{digests.pop()}"


# ---------------------------------------------------------------------------
# The files up writes
# ---------------------------------------------------------------------------


def _scalar(value: str) -> str:
    """*value* as a YAML string Compose reads as it is: quoted, and with
    nothing it would interpolate."""
    if _UNSAFE_VALUE.search(value):
        raise _refused(f"{value!r} cannot be written into a compose file")
    return json.dumps(value)


def render(project: Project, *, image: str, settings: Path, port: int, telemetry: bool,
           jwt_key: Optional[str], ca_bundle: str) -> str:
    """up's compose file: the sidecar service, its volumes, and what the
    gateway's service gains (the socket's volume, the start order, the
    telemetry choice)."""
    mounts = [(project.gateway_toml.parent.as_posix(), GATEWAY_FOLDER)]
    if jwt_key:
        mounts.append((jwt_key, JWT_KEY))
    if ca_bundle:
        mounts.append((ca_bundle, ca_bundle))
    binds = "".join(
        f"      - type: bind\n        source: {_scalar(source)}\n"
        f"        target: {_scalar(target)}\n        read_only: true\n"
        for source, target in mounts)
    probe = ("import urllib.request; urllib.request.urlopen("
             f"'http://127.0.0.1:{int(port)}/healthz', timeout=2)")
    folder = str(PurePosixPath(SOCKET).parent)
    return (
        "# Written by `artzain connect openshell up`; `artzain connect openshell remove`\n"
        "# deletes it. The project's .env adds it to COMPOSE_FILE. Do not edit.\n"
        "services:\n"
        f"  {SERVICE}:\n"
        f"    image: {_scalar(image)}\n"
        "    restart: unless-stopped\n"
        # The host's network, as the native sidecar: its routes on this
        # host's loopback only, and the engine reached as this host reaches it.
        "    network_mode: host\n"
        "    read_only: true\n"
        "    cap_drop: [\"ALL\"]\n"
        "    security_opt: [\"no-new-privileges:true\"]\n"
        f"    env_file: [{_scalar(settings.as_posix())}]\n"
        "    volumes:\n"
        f"      - {_scalar(SOCKET_VOLUME + ':' + folder)}\n"
        f"      - {_scalar(STATE_VOLUME + ':' + STATE)}\n"
        f"{binds}"
        "    healthcheck:\n"
        f"      test: [\"CMD\", \"python\", \"-c\", {json.dumps(probe)}]\n"
        "      interval: 5s\n"
        "      timeout: 3s\n"
        "      retries: 6\n"
        "      start_period: 30s\n"
        f"  {project.service}:\n"
        # The gateway refuses to start while its interceptor does not answer.
        "    depends_on:\n"
        f"      {SERVICE}:\n"
        "        condition: service_healthy\n"
        "    environment:\n"
        f"      OPENSHELL_TELEMETRY_ENABLED: \"{'true' if telemetry else 'false'}\"\n"
        "    volumes:\n"
        f"      - {_scalar(SOCKET_VOLUME + ':' + folder)}\n"
        "volumes:\n"
        f"  {SOCKET_VOLUME}: {{}}\n"
        f"  {STATE_VOLUME}: {{}}\n"
    )


def compose_file_line(project: Project, ours: Path) -> str:
    """The ``.env`` line that adds *ours* to the files the project is
    brought up from."""
    return "COMPOSE_FILE=" + ":".join((*project.files, ours.as_posix()))


_SETS_COMPOSE_FILE = re.compile(r"^\s*(?:export\s+)?COMPOSE_FILE\s*=", re.MULTILINE)


def sets_compose_file(env_text: str) -> bool:
    """Whether an ``.env`` (without up's block) sets ``COMPOSE_FILE``."""
    return bool(_SETS_COMPOSE_FILE.search(env_text))


__all__ = ["FILE", "GATEWAY_IMAGE", "Mount", "Project", "SERVICE", "SIDECAR_IMAGE", "SIGNER",
           "check", "config_hash", "containers", "find", "jwt", "operator_hash", "pinned",
           "preflight", "remove_sidecar", "render", "stays_up", "up", "verify_image", "version"]
