"""NVIDIA's OpenShell chart on Kubernetes, as ``artzain connect openshell
--kubernetes`` binds it.

NVIDIA publishes the gateway's Helm chart at :data:`CHART` (its ``name`` is
``helm-chart``; its pods are labelled ``app.kubernetes.io/name=openshell``).
The chart (0.1.3 on) carries what binding needs in its values but one thing:

* ``gatewayConfig`` renders into the gateway's ``gateway.toml``. Table names
  are dotted top-level keys: the registration goes under
  ``gatewayConfig["openshell.gateway"].interceptors``;
* ``server.extraVolumes`` and ``server.extraVolumeMounts`` give the gateway
  the folder of the sidecar's socket, an ``emptyDir``;
* it has no hook for a second container. Until it has one, ``up`` runs
  ``helm upgrade`` with ``artzain`` as Helm's post-renderer
  (:func:`post_render`), which adds the sidecar to the gateway's pod with
  ``kubectl kustomize`` and a strategic merge patch (written as JSON, which
  YAML reads): nothing here parses YAML. The patch merges by name, so it
  keeps any init container or volume the chart's own workload has.

The sidecar is a native sidecar (an init container that keeps running), so
the kubelet starts it, and waits for its startup probe, before the gateway.
It runs as the gateway's user, so the ``0600`` socket it makes, in a ``0700``
folder of its own inside the ``emptyDir`` (which is ``2777``), is the
gateway's to open. It checks the gateway's signed calls with the chart's JWT
key Secret, reads the rendered ``gateway.toml`` from the chart's ConfigMap
for its heartbeat, and lists sandboxes with the image's ``openshell`` CLI
over mTLS, with the chart's client certificate. Its settings are a Secret,
``<fullname>-artzain``, which it reads through ``envFrom``; the operator's
machine keeps no credential.

A gateway whose pod lost the sidecar (a ``helm upgrade`` without the
post-renderer, say) does not start: its interceptor is ``fail_closed``.
``doctor`` says so; :func:`helm_args` gives the arguments an operator adds to
their own ``helm upgrade``.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

#: NVIDIA's chart, as published, and what Helm records as its name.
CHART = "oci://ghcr.io/nvidia/openshell/helm-chart"
CHART_NAME = "helm-chart"
#: The chart's pods, and its gateway container.
NAME_LABEL = "app.kubernetes.io/name"
NAME = "openshell"
INSTANCE_LABEL = "app.kubernetes.io/instance"
GATEWAY_CONTAINER = "openshell-gateway"
#: The sidecar's container, and where it keeps what it makes.
SIDECAR = "artzain-sidecar"
RUN_VOLUME = "artzain-run"
STATE_VOLUME = "artzain-state"
JWT_VOLUME = "artzain-gateway-jwt"
TLS_VOLUME = "artzain-client-tls"
CA_VOLUME = "artzain-ca"
RUN = "/run/artzain"
SOCKET = RUN + "/sock/openshell.sock"
STATE = "/var/lib/artzain"
#: The sidecar's own files: in a folder it makes, since kubelet makes the
#: volume's own folder root's and the sidecar's private files refuse that.
DATA = STATE + "/sidecar"
HOME = STATE + "/home"
JWT_KEY = "/etc/artzain/jwt/public.pem"
#: A private certificate authority's bundle: its ConfigMap's key, and where
#: the sidecar reads it.
CA_KEY = "ca-bundle.pem"
CA_BUNDLE = "/etc/artzain/ca/" + CA_KEY
#: The most a CA bundle may hold (a ConfigMap holds at most 1 MiB).
CA_MAX_BYTES = 256 * 1024
GATEWAY_TOML = "/etc/artzain/gateway/gateway.toml"
CLI = "/usr/local/bin/openshell"
#: The chart's ConfigMap volume of gateway.toml, which the sidecar mounts too.
CONFIG_VOLUME = "gateway-config"
#: The chart's client certificate Secret, by default.
CLIENT_TLS = "openshell-client-tls"
#: The volumes ``up`` adds through the chart's values.
OUR_VOLUMES = (RUN_VOLUME, STATE_VOLUME)

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def _refused(message: str) -> Exception:
    from artzain.openshell.connect import ConnectError

    return ConnectError(message)


def endpoint(port: int) -> str:
    """The gateway as the sidecar's CLI reaches it, inside the pod."""
    return f"https://127.0.0.1:{int(port)}"


def mtls_folder(port: int) -> str:
    """Where the CLI, given :func:`endpoint`, reads its mTLS files."""
    return f"{HOME}/.config/openshell/gateways/https___127.0.0.1_{int(port)}/mtls"


def settings_name(fullname: str) -> str:
    """The name of the Secret that holds the sidecar's settings. (Named for
    what it returns: CodeQL reads a call to a function named like a secret
    as a secret, and up, remove and doctor say this name.)"""
    return f"{fullname}-artzain"


def ca_configmap(fullname: str) -> str:
    """The ConfigMap of the authorities the sidecar trusts for the engine."""
    return f"{fullname}-artzain-ca"


def ca_bundle_text(path: str) -> str:
    """The PEM bundle at *path*, read on this machine for the cluster, once
    Python's TLS has loaded a certificate from it."""
    import ssl
    from pathlib import Path

    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise _refused(f"--ca-bundle {path} cannot be read ({exc.strerror or type(exc).__name__})"
                       ) from None
    if len(data) > CA_MAX_BYTES:
        raise _refused(f"--ca-bundle {path} is larger than {CA_MAX_BYTES // 1024} KiB")
    try:
        text = data.decode("ascii")
        loaded = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        loaded.load_verify_locations(cadata=text)
    except (UnicodeDecodeError, ssl.SSLError, ValueError):
        loaded = None
    if loaded is None or not loaded.cert_store_stats().get("x509"):
        raise _refused(f"--ca-bundle {path} holds no PEM certificate that can be read")
    return "".join(line + "\n" for line in text.splitlines())


# ---------------------------------------------------------------------------
# The chart's values
# ---------------------------------------------------------------------------


def _interceptors(registration: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """The interceptor tables of a parsed registration
    (:func:`artzain.openshell.registration.render`, as TOML)."""
    found = (((registration.get("openshell") or {}).get("gateway") or {})
             .get("interceptors") or [])
    if not isinstance(found, list) or not found:
        raise _refused("the registration holds no interceptor")
    return [dict(entry) for entry in found]


def ours(values: Mapping[str, Any]) -> Dict[str, Any]:
    """What of *values* is ``up``'s: its interceptors and its two volumes."""
    from artzain.openshell import registration

    def as_map(found: Any) -> Mapping[str, Any]:
        return found if isinstance(found, dict) else {}

    def as_list(found: Any) -> List[Any]:
        return found if isinstance(found, list) else []

    gateway = as_map(as_map(values.get("gatewayConfig")).get("openshell.gateway"))
    server = as_map(values.get("server"))
    return {
        "interceptors": [i for i in as_list(gateway.get("interceptors"))
                         if isinstance(i, dict) and i.get("name") in registration.NAMES],
        "volumes": [v for v in as_list(server.get("extraVolumes"))
                    if isinstance(v, dict) and v.get("name") in OUR_VOLUMES],
        "mounts": [m for m in as_list(server.get("extraVolumeMounts"))
                   if isinstance(m, dict) and m.get("name") == RUN_VOLUME],
    }


def bound(values: Mapping[str, Any], registration: Mapping[str, Any], *,
          telemetry: bool, replace: bool = False) -> Dict[str, Any]:
    """*values* (the release's own, as ``helm get values`` gives them) with
    the registration and the socket's folder added, and the telemetry choice
    set. Anything of the operator's stays. An ArtzAIn registration already
    there is replaced when *replace* says ``up`` put it (its record for this
    release); else it is refused, as is a gateway table ``up`` cannot add
    to."""
    if not replace and ours(values)["interceptors"]:
        names = sorted({i["name"] for i in ours(values)["interceptors"]})
        raise _refused(f"the release's values already register {', '.join(names)}: take that "
                       "registration out, then run this again")
    out = without(values)
    config = out.setdefault("gatewayConfig", {})
    if not isinstance(config, dict):
        raise _refused("the release's gatewayConfig is not a map")
    if isinstance(config.get("openshell"), dict) and "gateway" in config["openshell"]:
        raise _refused('the release\'s values give gatewayConfig.openshell.gateway as a nested '
                       'map: the chart takes it as the dotted key "openshell.gateway" only')
    gateway = config.setdefault("openshell.gateway", {})
    if not isinstance(gateway, dict):
        raise _refused('the release\'s gatewayConfig["openshell.gateway"] is not a map')
    existing = gateway.setdefault("interceptors", [])
    if not isinstance(existing, list):
        raise _refused('the release\'s gatewayConfig["openshell.gateway"].interceptors is '
                       "not a list")
    existing.extend(_interceptors(registration))
    server = out.setdefault("server", {})
    if not isinstance(server, dict):
        raise _refused("the release's server values are not a map")
    for key, entries in (("extraVolumes", [{"name": RUN_VOLUME, "emptyDir": {}},
                                           {"name": STATE_VOLUME, "emptyDir": {}}]),
                         ("extraVolumeMounts", [{"name": RUN_VOLUME, "mountPath": RUN}])):
        found = server.setdefault(key, [])
        if not isinstance(found, list):
            raise _refused(f"the release's server.{key} is not a list")
        found.extend(entries)
    server["telemetryEnabled"] = bool(telemetry)
    return out


def without(values: Mapping[str, Any]) -> Dict[str, Any]:
    """*values* without anything of ``up``'s, as the operator had them
    (keys ``up`` added and left empty are taken out again)."""
    from artzain.openshell import registration as reg

    out = copy.deepcopy(dict(values))
    config = out.get("gatewayConfig")
    if isinstance(config, dict) and isinstance(config.get("openshell.gateway"), dict):
        gateway = config["openshell.gateway"]
        if isinstance(gateway.get("interceptors"), list):
            gateway["interceptors"] = [i for i in gateway["interceptors"]
                                       if not (isinstance(i, dict) and i.get("name") in reg.NAMES)]
            if not gateway["interceptors"]:
                del gateway["interceptors"]
        if not gateway:
            del config["openshell.gateway"]
        if not config:
            del out["gatewayConfig"]
    server = out.get("server")
    if isinstance(server, dict):
        for key, names in (("extraVolumes", OUR_VOLUMES), ("extraVolumeMounts", (RUN_VOLUME,))):
            if isinstance(server.get(key), list):
                server[key] = [e for e in server[key]
                               if not (isinstance(e, dict) and e.get("name") in names)]
                if not server[key]:
                    del server[key]
    return out


# ---------------------------------------------------------------------------
# The post-renderer's patch
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Render:
    """What the post-renderer needs to add the sidecar: nothing secret.
    The sidecar's settings are in :func:`settings_name`."""

    kind: str                  # StatefulSet or Deployment
    release: str               # the Helm release (the instance label)
    fullname: str              # the chart's fullname
    image: str                 # the sidecar image, by digest
    uid: int
    gid: int
    port: int                  # the gateway's gRPC port in the pod
    gateway_id: str            # the id the gateway signs its calls with
    jwt_secret: str = ""       # the chart's JWT key Secret, or none
    client_tls: str = CLIENT_TLS
    sidecar_port: int = 8088
    ca_bundle: str = ""        # the ConfigMap of a private CA, or none

    def check(self) -> None:
        if self.kind not in ("StatefulSet", "Deployment"):
            raise _refused(f"the gateway runs as a {self.kind}, which this release cannot bind")
        for name in (self.release, self.fullname, self.client_tls) + tuple(
                name for name in (self.jwt_secret, self.ca_bundle) if name):
            if not _NAME.match(name):
                raise _refused(f"{name!r} is not a Kubernetes name")
        if not _DIGEST.match(self.image):
            raise _refused("the sidecar image must be named by its digest")
        for number in (self.uid, self.gid):
            if isinstance(number, bool) or not isinstance(number, int) or number < 1:
                raise _refused("the gateway runs as root, or as no user this release can match: "
                               "the sidecar runs as the gateway's own user")
        for number in (self.port, self.sidecar_port):
            if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 65535:
                raise _refused(f"{number!r} is not a port")

    def args(self) -> List[str]:
        """The post-renderer's arguments, as Helm passes them."""
        out = ["--kind", self.kind, "--release", self.release, "--fullname", self.fullname,
               "--image", self.image, "--uid", str(self.uid), "--gid", str(self.gid),
               "--port", str(self.port), "--gateway-id", self.gateway_id,
               "--client-tls", self.client_tls, "--sidecar-port", str(self.sidecar_port)]
        if self.jwt_secret:
            out += ["--jwt-secret", self.jwt_secret]
        if self.ca_bundle:
            out += ["--ca-bundle-configmap", self.ca_bundle]
        return out


def sidecar(render: Render) -> Dict[str, Any]:
    """The sidecar's container: a native sidecar, as the gateway's user."""
    probe = ("import urllib.request; urllib.request.urlopen("
             f"'http://127.0.0.1:{render.sidecar_port}/healthz', timeout=2)")
    env = [
        {"name": "OPENSHELL_SIDECAR_GRPC", "value": f"unix://{SOCKET}"},
        {"name": "OPENSHELL_SIDECAR_HOST", "value": "127.0.0.1"},
        {"name": "OPENSHELL_SIDECAR_PORT", "value": str(render.sidecar_port)},
        {"name": "OPENSHELL_SIDECAR_STATE", "value": f"{DATA}/state.json"},
        {"name": "OPENSHELL_SIDECAR_JOURNAL", "value": f"{DATA}/journal.json"},
        {"name": "OPENSHELL_SIDECAR_BASE_POLICY", "value": f"{DATA}/base-policy.json"},
        {"name": "OPENSHELL_GATEWAY_TOML", "value": GATEWAY_TOML},
        {"name": "OPENSHELL_SIDECAR_LIST_CLI", "value": CLI},
        {"name": "OPENSHELL_GATEWAY_ENDPOINT", "value": endpoint(render.port)},
        {"name": "HOME", "value": HOME},
    ]
    mounts = [
        {"name": RUN_VOLUME, "mountPath": RUN},
        {"name": STATE_VOLUME, "mountPath": STATE},
        {"name": CONFIG_VOLUME, "mountPath": GATEWAY_TOML.rsplit("/", 1)[0], "readOnly": True},
        {"name": TLS_VOLUME, "mountPath": mtls_folder(render.port), "readOnly": True},
    ]
    if render.jwt_secret:
        env += [{"name": "OPENSHELL_JWT_PUBLIC_KEY", "value": JWT_KEY},
                {"name": "OPENSHELL_JWT_GATEWAY_ID", "value": render.gateway_id}]
        mounts.append({"name": JWT_VOLUME, "mountPath": JWT_KEY.rsplit("/", 1)[0],
                       "readOnly": True})
    if render.ca_bundle:
        env.append({"name": "OPENSHELL_SIDECAR_CA_BUNDLE", "value": CA_BUNDLE})
        mounts.append({"name": CA_VOLUME, "mountPath": CA_BUNDLE.rsplit("/", 1)[0],
                       "readOnly": True})
    return {
        "name": SIDECAR,
        "image": render.image,
        "restartPolicy": "Always",
        "envFrom": [{"secretRef": {"name": settings_name(render.fullname)}}],
        "env": env,
        "securityContext": {
            "runAsUser": render.uid,
            "runAsGroup": render.gid,
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": mounts,
        "startupProbe": {"exec": {"command": ["python", "-c", probe]},
                         "periodSeconds": 2, "failureThreshold": 60},
    }


def patch(render: Render) -> Dict[str, Any]:
    """The strategic merge patch ``kubectl kustomize`` applies to the
    gateway's workload: the sidecar, and the volumes it reads (two Secrets,
    and a private CA's ConfigMap when there is one).
    It merges by name; kustomize applies it to the target its kustomization
    selects, whatever name the patch itself carries."""
    render.check()
    volumes: List[Dict[str, Any]] = [{
        "name": TLS_VOLUME,
        "secret": {"secretName": render.client_tls, "defaultMode": 0o400, "items": [
            {"key": "ca.crt", "path": "ca.crt"},
            {"key": "tls.crt", "path": "tls.crt"},
            {"key": "tls.key", "path": "tls.key"}]}}]
    if render.jwt_secret:
        volumes.append({"name": JWT_VOLUME,
                        "secret": {"secretName": render.jwt_secret, "defaultMode": 0o444,
                                   "items": [{"key": "public.pem", "path": "public.pem"}]}})
    if render.ca_bundle:
        volumes.append({"name": CA_VOLUME,
                        "configMap": {"name": render.ca_bundle, "defaultMode": 0o444,
                                      "items": [{"key": CA_KEY, "path": CA_KEY}]}})
    return {"apiVersion": "apps/v1", "kind": render.kind,
            "metadata": {"name": render.fullname},
            "spec": {"template": {"spec": {"initContainers": [sidecar(render)],
                                           "volumes": volumes}}}}


def kustomization(render: Render) -> str:
    """The kustomization the post-renderer runs: its own patch, on the
    release's gateway workload alone."""
    selector = f"{NAME_LABEL}={NAME},{INSTANCE_LABEL}={render.release}"
    return ("resources:\n  - all.yaml\npatches:\n  - path: sidecar.json\n    target:\n"
            f"      kind: {render.kind}\n      labelSelector: {json.dumps(selector)}\n")


def post_render(manifests: str, render: Render, run: Any) -> str:
    """Helm's post-renderer: *manifests* with the sidecar added, by
    ``kubectl kustomize`` (*run* takes argv and a folder, returns its
    output). Refused when the result holds no sidecar, which is what a
    patch that matched no workload gives."""
    import tempfile
    from pathlib import Path

    smp = patch(render)
    with tempfile.TemporaryDirectory(prefix="artzain-kube-render-") as folder:
        where = Path(folder)
        (where / "all.yaml").write_text(manifests, encoding="utf-8")
        (where / "sidecar.json").write_text(json.dumps(smp), encoding="utf-8")
        (where / "kustomization.yaml").write_text(kustomization(render), encoding="utf-8")
        out = run(["kubectl", "kustomize", folder])
    if f"name: {SIDECAR}" not in out:
        raise _refused(f"the post-renderer found no {render.kind} of release {render.release} "
                       "to add the sidecar to")
    return out


def helm_args(python: str, render: Render) -> List[str]:
    """The arguments that make Helm run this post-renderer, for an operator's
    own ``helm upgrade`` of a bound release."""
    args = ["-m", "artzain.cli", "openshell", "kube-render", *render.args()]
    return ["--post-renderer", python, *[x for a in args for x in ("--post-renderer-args", a)]]


def ca_manifest(fullname: str, namespace: str, pem: str) -> Dict[str, Any]:
    """A private CA's bundle, as a ConfigMap ``kubectl apply`` takes: it is
    no secret."""
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": ca_configmap(fullname), "namespace": namespace,
                         "labels": {"app.kubernetes.io/managed-by": "artzain",
                                    INSTANCE_LABEL: fullname}},
            "data": {CA_KEY: pem}}


def secret_manifest(fullname: str, namespace: str, settings: Mapping[str, str]) -> Dict[str, Any]:
    """The sidecar's settings, as a Secret ``kubectl apply`` takes."""
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": settings_name(fullname), "namespace": namespace,
                         "labels": {"app.kubernetes.io/managed-by": "artzain",
                                    INSTANCE_LABEL: fullname}},
            "stringData": dict(settings)}


# ---------------------------------------------------------------------------
# The release, as the cluster runs it
# ---------------------------------------------------------------------------

#: The volume of the chart's JWT key Secret on the gateway's pod.
CHART_JWT_VOLUME = "sandbox-jwt"
#: How long ``up`` waits for the sidecar to have tried both reports.
REPORTS_WAIT_SECONDS = 60.0
_SEMVER = re.compile(r"\d+\.\d+\.\d+")


@dataclass(frozen=True)
class Target:
    """Which release, and where: the kube context, its namespace, its name."""

    context: str
    namespace: str
    release: str

    def slug(self) -> str:
        """The name of this target's connect record."""
        return re.sub(r"[^A-Za-z0-9_.-]", "_", f"{self.context}.{self.namespace}.{self.release}")


@dataclass(frozen=True)
class Release:
    """The release as the cluster runs it: what ``up`` needs to bind it."""

    target: Target
    chart_version: str
    openshell_version: str
    kind: str
    fullname: str
    uid: int
    gid: int
    port: int
    gateway_id: str
    jwt_secret: str
    client_tls: str
    config_map: str
    sidecar_image: str = ""    # the sidecar the workload's template holds, or none

    def render(self, image: str, sidecar_port: int, ca_bundle: str = "") -> Render:
        return Render(kind=self.kind, release=self.target.release, fullname=self.fullname,
                      image=image, uid=self.uid, gid=self.gid, port=self.port,
                      gateway_id=self.gateway_id, jwt_secret=self.jwt_secret,
                      client_tls=self.client_tls, sidecar_port=sidecar_port,
                      ca_bundle=ca_bundle)

    def facts(self) -> Dict[str, Any]:
        return {"context": self.target.context, "namespace": self.target.namespace,
                "release": self.target.release, "fullname": self.fullname, "kind": self.kind,
                "chart_version": self.chart_version, "openshell_version": self.openshell_version}


def _said(done: Any) -> str:
    from artzain.openshell.connect import _said as said

    return said(done)[-300:]


def _helm(host: Any, target: Target, *args: str, timeout: float = 120.0) -> Any:
    return host.run("helm", "--kube-context", target.context, "--namespace", target.namespace,
                    *args, timeout=timeout)


def _kubectl(host: Any, target: Target, *args: str, timeout: float = 120.0) -> Any:
    return host.run("kubectl", "--context", target.context, "--namespace", target.namespace,
                    *args, timeout=timeout)


def _json(done: Any, what: str) -> Any:
    if done.returncode != 0:
        raise _refused(f"{what} failed: {_said(done)}")
    try:
        return json.loads(done.stdout or "null")
    except ValueError:
        raise _refused(f"{what} did not print JSON") from None


def target(host: Any, *, namespace: str, release: str, context: str = "") -> Target:
    """The release to bind, in *context* (kubectl's current one when empty)."""
    for tool in ("kubectl", "helm"):
        if not host.which(tool):
            raise _refused(f"{tool} is not on PATH: the Kubernetes connect runs kubectl and helm "
                           "as you, with your cluster access")
    for what, name in (("--namespace", namespace), ("--release", release)):
        if not _NAME.match(name or ""):
            raise _refused(f"{what} {name!r} is not a Kubernetes name")
    if not context:
        done = host.run("kubectl", "config", "current-context", timeout=30)
        context = (done.stdout or "").strip()
        if done.returncode != 0 or not context:
            raise _refused("kubectl has no current context: name one with --kube-context")
    if any(ch.isspace() for ch in context):
        raise _refused(f"--kube-context {context!r} is not a context name")
    return Target(context, namespace, release)


def selector(release: str) -> str:
    return f"{NAME_LABEL}={NAME},{INSTANCE_LABEL}={release}"


def user_values(host: Any, target: Target) -> Dict[str, Any]:
    """The values the release was installed or upgraded with (not the
    chart's defaults)."""
    found = _json(_helm(host, target, "get", "values", target.release, "-o", "json"),
                  f"helm get values {target.release}")
    if found is None:
        return {}
    if not isinstance(found, dict):
        raise _refused(f"helm get values {target.release} did not give a map")
    return found


def gateway_toml(host: Any, target: Target, config_map: str) -> str:
    found = _json(_kubectl(host, target, "get", "configmap", config_map, "-o", "json"),
                  f"kubectl get configmap {config_map}")
    text = ((found or {}).get("data") or {}).get("gateway.toml")
    if not isinstance(text, str):
        raise _refused(f"ConfigMap {config_map} holds no gateway.toml")
    return text


def find(host: Any, target: Target) -> Release:
    """The release, when it is NVIDIA's chart running one gateway workload
    that this release can bind. Raises with what is not."""
    import tomllib

    meta = _json(_helm(host, target, "get", "metadata", target.release, "-o", "json"),
                 f"helm get metadata {target.release} (in {target.namespace}, context "
                 f"{target.context})")
    if not isinstance(meta, dict) or meta.get("chart") != CHART_NAME:
        raise _refused(f"release {target.release} runs the chart "
                       f"{(meta or {}).get('chart')!r}, not NVIDIA's OpenShell chart ({CHART})")
    chart_version = str(meta.get("version") or "")
    openshell_version = str(meta.get("appVersion") or "").lstrip("v")
    if not (_SEMVER.fullmatch(chart_version) and _SEMVER.fullmatch(openshell_version)):
        raise _refused(f"release {target.release} does not say its chart and OpenShell versions")
    found = _json(_kubectl(host, target, "get", "statefulsets,deployments", "-l",
                           selector(target.release), "-o", "json"), "kubectl get statefulsets")
    items = (found or {}).get("items") or []
    if len(items) != 1:
        raise _refused(f"release {target.release} runs {len(items)} gateway workloads, not one")
    workload = items[0]
    spec = workload.get("spec", {}).get("template", {}).get("spec", {})
    gateway = next((c for c in spec.get("containers") or []
                    if c.get("name") == GATEWAY_CONTAINER), None)
    ours_now = next((c for c in spec.get("initContainers") or [] if c.get("name") == SIDECAR), {})
    if gateway is None:
        raise _refused(f"release {target.release}'s workload has no {GATEWAY_CONTAINER} container")
    own, pod = gateway.get("securityContext") or {}, spec.get("securityContext") or {}
    uid = own.get("runAsUser", pod.get("runAsUser"))
    gid = own.get("runAsGroup", pod.get("runAsGroup", uid))
    port = next((p.get("containerPort") for p in gateway.get("ports") or []
                 if p.get("name") == "grpc"), None)
    if not isinstance(port, int):
        raise _refused(f"the {GATEWAY_CONTAINER} container names no grpc port")
    volumes = {v.get("name"): v for v in spec.get("volumes") or []}
    config_map = ((volumes.get(CONFIG_VOLUME) or {}).get("configMap") or {}).get("name") or ""
    if not config_map:
        raise _refused(f"the gateway's pod mounts no {CONFIG_VOLUME} ConfigMap")
    jwt_secret = ((volumes.get(CHART_JWT_VOLUME) or {}).get("secret") or {}).get("secretName") or ""
    try:
        config = tomllib.loads(gateway_toml(host, target, config_map))
    except tomllib.TOMLDecodeError:
        raise _refused(f"ConfigMap {config_map}'s gateway.toml is not TOML") from None
    signer = ((config.get("openshell") or {}).get("gateway") or {}).get("gateway_jwt") or {}
    gateway_id = str(signer.get("gateway_id") or "") if jwt_secret else ""
    every = _json(_helm(host, target, "get", "values", target.release, "--all", "-o", "json"),
                  f"helm get values {target.release} --all") or {}
    client_tls = (((every.get("server") or {}).get("tls") or {}).get("clientTlsSecretName")
                  or CLIENT_TLS)
    return Release(target, chart_version, openshell_version, str(workload.get("kind")),
                   str(workload.get("metadata", {}).get("name") or ""),
                   uid if isinstance(uid, int) else 0, gid if isinstance(gid, int) else 0,
                   port, gateway_id if gateway_id else "", jwt_secret if gateway_id else "",
                   str(client_tls), config_map, str(ours_now.get("image") or ""))


def _pods(host: Any, target: Target) -> List[Dict[str, Any]]:
    found = _json(_kubectl(host, target, "get", "pods", "-l", selector(target.release),
                           "-o", "json"), "kubectl get pods")
    # The chart's hook Jobs have pods with the release's labels too.
    gateways = [pod for pod in (found or {}).get("items") or []
                if any(c.get("name") == GATEWAY_CONTAINER
                       for c in (pod.get("spec") or {}).get("containers") or [])]
    return sorted(gateways, key=lambda p: p["metadata"]["name"])


def _running(container: Dict[str, Any]) -> bool:
    """The container's state is running: the key says it, since its one
    field (``startedAt``) may be absent."""
    state = container.get("state")
    return isinstance(state, dict) and "running" in state


def _pod(host: Any, target: Target) -> str:
    """A running pod of the gateway's, with the sidecar in it."""
    for pod in _pods(host, target):
        statuses = (pod.get("status") or {}).get("initContainerStatuses") or []
        if any(s.get("name") == SIDECAR and _running(s) for s in statuses):
            return str(pod["metadata"]["name"])
    raise _refused(f"no pod of release {target.release} runs the ArtzAIn sidecar")


class InSidecar:
    """A host whose ``openshell`` runs inside the sidecar's container, as
    the gateway's own CLI sees it there, with neither the credential nor the
    sidecar's token in its environment: ``up``'s self-test needs no CLI, no
    port-forward and no client certificate on this machine."""

    def __init__(self, host: Any, target: Target, pod: str) -> None:
        self.host, self.target, self.pod = host, target, pod

    def run(self, *argv: str, timeout: float = 60.0) -> Any:
        if argv[:1] != ("openshell",):
            raise ValueError(f"only the openshell CLI runs in the sidecar, not {argv[:1]}")
        return _kubectl(self.host, self.target, "exec", self.pod, "-c", SIDECAR, "--",
                        "env", "-u", "COGNEXUS_API_KEY", "-u", "OPENSHELL_SIDECAR_TOKEN",
                        "NO_COLOR=1", CLI, *argv[1:], timeout=timeout)


#: Asks the sidecar, from inside its container, what the engine took.
_REPORTS = ("import json, os, urllib.request; "
            "port = os.environ.get('OPENSHELL_SIDECAR_PORT', '8088'); "
            "ask = urllib.request.Request('http://127.0.0.1:%s/artzain/reports' % port, "
            "headers={'Authorization': 'Bearer ' + os.environ.get('OPENSHELL_SIDECAR_TOKEN', '')}); "
            "print(urllib.request.urlopen(ask, timeout=10).read().decode())")


def reports(host: Any, target: Target, pod: str) -> Optional[Dict[str, Any]]:
    done = _kubectl(host, target, "exec", pod, "-c", SIDECAR, "--", "python", "-c", _REPORTS,
                    timeout=60)
    try:
        found = json.loads(done.stdout or "") if done.returncode == 0 else None
    except ValueError:
        return None
    return found if isinstance(found, dict) else None


def _settings(host: Any, target: Target, fullname: str) -> Dict[str, str]:
    """The sidecar's settings Secret, decoded; empty when there is none."""
    import base64

    done = _kubectl(host, target, "get", "secret", settings_name(fullname), "-o", "json",
                    "--ignore-not-found")
    found = _json(done, f"kubectl get secret {settings_name(fullname)}")
    data = (found or {}).get("data") or {}
    try:
        return {k: base64.b64decode(v).decode("utf-8") for k, v in data.items()}
    except (ValueError, UnicodeDecodeError):
        raise _refused(f"Secret {settings_name(fullname)} cannot be read") from None


def _apply(host: Any, target: Target, manifest: Mapping[str, Any], what: str) -> None:
    """``kubectl apply`` *manifest*, from a file of this user's alone that is
    gone when this returns: a credential never reaches a command line."""
    import tempfile
    from pathlib import Path

    from artzain._private_files import private_dir, write_private
    from artzain.openshell.connect import layout

    folder = private_dir(layout(host).state_dir)
    with tempfile.TemporaryDirectory(prefix="kube-", dir=folder) as where:
        path = Path(where) / "manifest.json"
        write_private(path, json.dumps(manifest).encode("utf-8"))
        done = _kubectl(host, target, "apply", "-f", str(path), timeout=60)
    if done.returncode != 0:
        raise _refused(f"writing {what} failed: {_said(done)}")


def _apply_secret(host: Any, target: Target, fullname: str, settings: Mapping[str, str]) -> None:
    """Write the settings Secret."""
    _apply(host, target, secret_manifest(fullname, target.namespace, settings),
           f"Secret {settings_name(fullname)}")


def _helm_upgrade(host: Any, release: Release, values: Mapping[str, Any], *,
                  render: Optional[Render] = None) -> None:
    """``helm upgrade`` the release to *values* (the whole of them), from
    NVIDIA's chart at the version it runs, with the post-renderer when a
    *render* says what to add."""
    import tempfile
    from pathlib import Path

    from artzain._private_files import private_dir, write_private
    from artzain.openshell.connect import layout

    target = release.target
    folder = private_dir(layout(host).state_dir)
    with tempfile.TemporaryDirectory(prefix="kube-", dir=folder) as where:
        file = Path(where) / "values.json"
        write_private(file, json.dumps(values, indent=1).encode("utf-8"))
        args = ["upgrade", target.release, CHART, "--version", release.chart_version,
                "--reset-values", "--values", str(file), "--timeout", "10m"]
        if render is not None:
            args += helm_args(host.executable, render)
        done = _helm(host, target, *args, timeout=900)
    if done.returncode != 0:
        raise _refused(f"helm upgrade {target.release} failed: {_said(done)}")


def _settle(host: Any, release: Release) -> None:
    """After an upgrade, the gateway's pods made again from the release's
    template. A StatefulSet does not replace a pod that never became ready
    (one a helm upgrade without the post-renderer left crash-looping, say):
    as Kubernetes says to, such a pod of an older revision is deleted, and
    the controller makes it again. Then waits for the rollout. (helm's own
    --wait would wait for that pod until it timed out.)"""
    if release.kind == "StatefulSet":
        target, seen = release.target, {}

        def observed() -> bool:
            found = _json(_kubectl(host, target, "get", "statefulset", release.fullname, "-o",
                                   "json"), f"kubectl get statefulset {release.fullname}") or {}
            seen["revision"] = (found.get("status") or {}).get("updateRevision") or ""
            return ((found.get("status") or {}).get("observedGeneration") or 0) >= (
                (found.get("metadata") or {}).get("generation") or 0)

        if _wait(host, 60.0, observed) and seen["revision"]:
            for pod in _pods(host, target):
                labels = (pod.get("metadata") or {}).get("labels") or {}
                ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                            for c in (pod.get("status") or {}).get("conditions") or [])
                if not ready and labels.get("controller-revision-hash") != seen["revision"]:
                    _kubectl(host, target, "delete", "pod", str(pod["metadata"]["name"]),
                             "--wait=false", timeout=60)
    _rolled_out(host, release)


def _rolled_out(host: Any, release: Release) -> None:
    done = _kubectl(host, release.target, "rollout", "status",
                    f"{release.kind.lower()}/{release.fullname}", "--timeout=5m", timeout=360)
    if done.returncode != 0:
        raise _refused(f"the gateway did not come up: {_said(done)}. See `kubectl logs` of its "
                       f"pod's {SIDECAR} and {GATEWAY_CONTAINER} containers")


def record_path(host: Any, target: Target) -> Any:
    from artzain.openshell.connect import layout

    return layout(host).artzain_dir / "kubernetes" / f"{target.slug()}.json"


def _registration(config: Any) -> Dict[str, Any]:
    import tomllib

    from artzain.openshell import registration

    return tomllib.loads(registration.render(f"unix://{SOCKET}",
                                             timeout_ms=config.interceptor_timeout_ms))


def _telemetry(values: Mapping[str, Any]) -> Optional[bool]:
    server = values.get("server")
    found = server.get("telemetryEnabled") if isinstance(server, dict) else None
    return found if isinstance(found, bool) else None


def _wait(host: Any, seconds: float, test: Any) -> bool:
    until = host.clock() + seconds
    while True:
        if test():
            return True
        if host.clock() >= until:
            return False
        host.sleep(2)


# ---------------------------------------------------------------------------
# up, remove, status, doctor, rotate-key
# ---------------------------------------------------------------------------


def up(host: Any, target: Target, *, token: str = "", digest: str = "", engine: str = "",
       proxy: str = "", ca_bundle: str = "", port: int = 8088, sidecar_image: str = "",
       out: Any = print) -> Dict[str, Any]:
    """Bind the release's gateway. Returns the record. Every step before the
    redeem checks what it can, so a release this cannot bind spends no
    token; a second run finishes a first that stopped."""
    import secrets

    from artzain.openshell import connect, registration

    if proxy == "env":
        raise _refused("--proxy env: the sidecar runs in the cluster, without this shell's proxy "
                       "settings; name the proxy (--proxy http://host:port)")
    if sys.version_info < (3, 11):
        raise _refused("artzain connect needs Python 3.11 or later (it reads TOML)")
    release = find(host, target)
    record = connect.Record.load(record_path(host, target))
    values = user_values(host, target)
    ours_before = record.done("upgraded")
    # Before the token: the values take the registration, and the pod the sidecar.
    trial = connect.ConnectConfig("https://engine.invalid", release.openshell_version)
    bound(values, _registration(trial), telemetry=False, replace=ours_before)
    image, image_release = connect._sidecar_image(host, record, sidecar_image, out)
    # A private CA: read here, and given to the sidecar in a ConfigMap. Once
    # given, it stays until remove.
    pem = ca_bundle_text(ca_bundle) if ca_bundle else ""
    if pem:
        ca_bundle, ca_map = os.path.abspath(ca_bundle), ca_configmap(release.fullname)
    else:
        ca_bundle = str(record.data.get("ca_bundle") or "")
        ca_map = str(record.data.get("ca_configmap") or "")
    render = release.render(image, int(port), ca_bundle=ca_map)
    render.check()

    if record.done("redeemed"):
        connect._say(out, f"gateway {record.data['gateway_id']}: already redeemed; using the "
                          f"credential in Secret {settings_name(release.fullname)}")
        config = connect.parse_config(record.data.get("config"))
        gateway_id = str(record.data["gateway_id"])
    else:
        if not token:
            raise _refused("set ARTZAIN_ENROLL_TOKEN to the enroll token you were given")
        got = connect.redeem(host, engine=engine, token=token, digest=digest, proxy=proxy,
                             ca_bundle=ca_bundle)
        config, gateway_id = got.config, got.gateway_id
        text = registration.render(f"unix://{SOCKET}", timeout_ms=config.interceptor_timeout_ms)
        settings = {
            "COGNEXUS_API_KEY": got.credential,
            "ARTZAIN_DECISION_URL": config.decision_url,
            "OPENSHELL_GATEWAY_ID": gateway_id,
            "OPENSHELL_SIDECAR_TOKEN": secrets.token_urlsafe(32),
            "OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS": str(config.decide_timeout_ms),
            "OPENSHELL_REGISTRATION_DIGEST": registration.digest(text),
        }
        if proxy:
            settings["OPENSHELL_SIDECAR_PROXY"] = proxy
        _apply_secret(host, target, release.fullname, settings)
        record.mark("redeemed", gateway_id=gateway_id, config=got.raw_config,
                    engine=engine.rstrip("/"), port=int(port), shape="kubernetes",
                    kubernetes=release.facts(), telemetry_before=_telemetry(values))
        connect._say(out, f"gateway {gateway_id}: credential saved in Secret "
                          f"{settings_name(release.fullname)} ({target.namespace})")
    if not connect._same_line(release.openshell_version, config.openshell_version):
        raise _refused(f"this gateway is OpenShell {release.openshell_version}, and the "
                       f"configuration was approved for {config.openshell_version}: upgrade the "
                       "release to that one, then run this again (no new token needed)")

    if pem:
        _apply(host, target, ca_manifest(release.fullname, target.namespace, pem),
               f"ConfigMap {ca_map}")
        record.mark("redeemed", ca_bundle=ca_bundle, ca_configmap=ca_map)

    # The registration and the sidecar, by one helm upgrade.
    wanted = bound(values, _registration(config), telemetry=config.telemetry, replace=ours_before)
    if (not record.done("upgraded") or wanted != values
            or record.data.get("render") != render.args() or release.sidecar_image != image):
        connect._say(out, f"helm upgrade {target.release}: the registration, and the ArtzAIn "
                          "sidecar beside the gateway")
        _helm_upgrade(host, release, wanted, render=render)
        record.mark("upgraded", sidecar_image=image, sidecar_image_release=image_release,
                    render=render.args())
    _settle(host, release)
    cli = InSidecar(host, target, _pod(host, target))

    if not record.done("approval-manual"):
        connect._check(connect._setting(cli, "manual"),
                       f"setting {connect.SELF_TEST_KEY} to manual")
        record.mark("approval-manual")
    decision = connect.self_test(cli)
    record.mark("self-test", self_test_decision_id=decision, connected=True)
    connect._say(out, f"gateway {gateway_id} is governed: the self-test write was refused by "
                      f"ArtzAIn decision {decision}.")
    receipt = connect.receipt_url(record.data.get("engine") or engine, decision)
    if receipt:
        connect._say(out, f"its receipt: {receipt}")
    seen: Dict[str, Any] = {}

    def tried() -> bool:
        seen["reports"] = found = reports(host, target, cli.pod)
        return isinstance(found, dict) and all(
            found.get(what) in ("ok", "failed") for what in ("heartbeat", "inventory"))

    _wait(host, REPORTS_WAIT_SECONDS, tried)
    record.mark("reported", reports=seen.get("reports"))
    connect._say(out, connect._reports_said(seen.get("reports")))
    return dict(record.data)


def remove(host: Any, target: Target, *, keep_credential: bool = False,
           out: Any = print) -> Dict[str, Any]:
    """Undo ``up``: the release upgraded back to the operator's own values
    (the gateway restarts unbound, without the sidecar), the credential
    revoked, and the settings Secret deleted."""
    from artzain.openshell import connect

    record = connect.Record.load(record_path(host, target))
    data = record.data
    facts = data.get("kubernetes") or {}
    result: Dict[str, Any] = {}
    fullname = str(facts.get("fullname") or "")
    try:
        release: Optional[Release] = find(host, target)
    except Exception as exc:  # noqa: BLE001 - a release gone is said, and the rest goes on
        release = None
        result["release"] = f"not found ({exc})"
    if release is not None:
        fullname = release.fullname
        values = user_values(host, target)
        mine = without(values)
        server = mine.get("server") if isinstance(mine.get("server"), dict) else None
        if "telemetry_before" in data and server is not None:
            if data["telemetry_before"] is None:
                server.pop("telemetryEnabled", None)
                if not server:
                    del mine["server"]
            else:
                server["telemetryEnabled"] = bool(data["telemetry_before"])
        if mine != values or data.get("connected") or record.done("upgraded"):
            _helm_upgrade(host, release, mine)
            _settle(host, release)
            result["gateway"] = "upgraded unbound, without the sidecar"
    if not fullname:
        record.delete()
        return result or {"nothing": "to remove"}
    settings = _settings(host, target, fullname)
    if settings.get("COGNEXUS_API_KEY") and data.get("gateway_id") and not keep_credential:
        revoked = connect.revoke(host, engine_url=str(data.get("engine") or connect.DEFAULT_ENGINE),
                                 gateway_id=str(data["gateway_id"]),
                                 credential=settings["COGNEXUS_API_KEY"],
                                 proxy=settings.get("OPENSHELL_SIDECAR_PROXY", ""),
                                 ca_bundle=str(data.get("ca_bundle") or ""))
        result["credential"] = "revoked" if revoked else "NOT revoked"
        if not revoked:
            record.mark("revoke-pending")
            connect._say(out, f"the engine could not revoke gateway {data['gateway_id']}'s "
                              "credential; Secret and record are kept so that running `remove` "
                              "again can revoke it")
            return result
    done = _kubectl(host, target, "delete", "secret", settings_name(fullname),
                    "--ignore-not-found", timeout=60)
    result["settings"] = "deleted" if done.returncode == 0 else f"NOT deleted: {_said(done)}"
    if data.get("ca_configmap"):
        done = _kubectl(host, target, "delete", "configmap", str(data["ca_configmap"]),
                        "--ignore-not-found", timeout=60)
        result["ca_bundle"] = "deleted" if done.returncode == 0 else f"NOT deleted: {_said(done)}"
    record.delete()
    connect._say(out, "removed: " + ", ".join(f"{k} {v}" for k, v in result.items()))
    return result


def _containers(host: Any, target: Target) -> Dict[str, Any]:
    """The first gateway pod's sidecar and gateway: running and ready."""
    pods = _pods(host, target)
    if not pods:
        return {"pod": None}
    status = pods[0].get("status") or {}
    by_name = {s.get("name"): s for s in (status.get("initContainerStatuses") or [])
               + (status.get("containerStatuses") or [])}

    def said(name: str) -> str:
        found = by_name.get(name)
        if found is None:
            return "absent"
        state = found.get("state") or {}
        if _running(found):
            return "ready" if found.get("ready") else "running"
        reason = (state.get("waiting") or state.get("terminated") or {}).get("reason")
        return str(reason or "not running")

    return {"pod": pods[0]["metadata"]["name"], "sidecar": said(SIDECAR),
            "gateway": said(GATEWAY_CONTAINER)}


def status(host: Any, target: Target) -> Dict[str, Any]:
    """What is bound, and whether it is up. Holds no credential."""
    from artzain.openshell import connect

    record = connect.Record.load(record_path(host, target)).data
    said: Dict[str, Any] = {
        "shape": "kubernetes", "context": target.context, "namespace": target.namespace,
        "release": target.release, "gateway_id": record.get("gateway_id"),
        "connected": bool(record.get("connected")),
        "self_test_decision_id": record.get("self_test_decision_id"),
        "self_test_receipt": connect.receipt_url(record.get("engine"),
                                                 record.get("self_test_decision_id")) or None,
    }
    try:
        release = find(host, target)
    except Exception as exc:  # noqa: BLE001 - status says what it could not read
        said["release_error"] = str(exc)
        return said
    values = user_values(host, target)
    toml = gateway_toml(host, target, release.config_map)
    said.update({
        "chart_version": release.chart_version,
        "openshell_version": release.openshell_version,
        "registration_in_values": bool(ours(values)["interceptors"]),
        "registration_in_gateway_toml": all(f'"{name}"' in toml for name in _names()),
        "credential_saved": bool(_settings(host, target, release.fullname)
                                 .get("COGNEXUS_API_KEY")),
        **_containers(host, target),
    })
    pod = said.get("pod")
    said["reports"] = reports(host, target, pod) if pod and said.get("sidecar") == "ready" else None
    image = record.get("sidecar_image")
    if image:
        said["helm_post_renderer"] = helm_args(host.executable, release.render(
            str(image), int(record.get("port") or 8088), str(record.get("ca_configmap") or "")))
    return said


def _names() -> List[str]:
    from artzain.openshell import registration

    return list(registration.NAMES)


#: Checks, from inside the sidecar, its socket and its folder.
_SOCKET = ("import os, stat; s = os.stat('" + SOCKET + "'); "
           "d = os.stat(os.path.dirname('" + SOCKET + "')); "
           "print(stat.S_ISSOCK(s.st_mode), oct(stat.S_IMODE(s.st_mode)), s.st_uid, "
           "oct(stat.S_IMODE(d.st_mode) & 0o777), d.st_uid)")


def doctor(host: Any, target: Target) -> Dict[str, Any]:
    """Check what binds the release's gateway, reading the cluster as you:
    the record, the release, its values, the pod's two containers, the
    socket, the registration the gateway reads, the release's OpenShell
    version, the CLI in the sidecar, and the sidecar's reports. ``ok`` is
    false when a check fails. Changes nothing."""
    from artzain.openshell import connect, registration

    checks: List[Dict[str, str]] = []

    def found(check: str, result: str, says: str) -> None:
        checks.append({"check": check, "result": result, "says": says})

    def answer() -> Dict[str, Any]:
        return {"ok": all(c["result"] != "fail" for c in checks), "checks": checks}

    data = connect.Record.load(record_path(host, target)).data
    if data.get("connected"):
        found("record", "ok", f"gateway {data.get('gateway_id')} is connected (self-test "
                              f"decision {data.get('self_test_decision_id')})")
    else:
        found("record", "fail", "this release is not connected: run `artzain connect openshell "
                                "up --kubernetes`")
    try:
        release = find(host, target)
    except Exception as exc:  # noqa: BLE001 - the check says what failed
        found("release", "fail", str(exc))
        return answer()
    found("release", "ok", f"release {target.release} runs NVIDIA's chart {release.chart_version} "
                           f"({release.kind} {release.fullname})")
    try:
        config = connect.parse_config(data["config"]) if data.get("config") else None
    except connect.ConnectError:
        config = None
    if config is None:
        found("versions", "warn", f"the gateway is OpenShell {release.openshell_version}; the "
                                  "record holds no approved release to compare with")
    elif not connect._same_line(release.openshell_version, config.openshell_version):
        found("versions", "fail", f"the gateway is OpenShell {release.openshell_version}, and the "
                                  f"configuration was approved for {config.openshell_version}")
    else:
        found("versions", "ok", f"the gateway is OpenShell {release.openshell_version}, as "
                                f"approved ({config.openshell_version})")

    values = user_values(host, target)
    if ours(values)["interceptors"]:
        found("values", "ok", "the release's values register ArtzAIn's interceptors")
    else:
        found("values", "fail", "the release's values hold no ArtzAIn registration: a helm "
                                "upgrade replaced them. Run `artzain connect openshell up "
                                "--kubernetes` again")
    settings = _settings(host, target, release.fullname)
    toml = gateway_toml(host, target, release.config_map)
    if config is not None and settings.get("OPENSHELL_REGISTRATION_DIGEST"):
        expected = registration.render(f"unix://{SOCKET}",
                                       timeout_ms=config.interceptor_timeout_ms)
        same = settings["OPENSHELL_REGISTRATION_DIGEST"] == registration.digest(expected)
        there = all(f'"{name}"' in toml for name in registration.NAMES) and SOCKET in toml
        found("registration", "ok" if same and there else "fail",
              f"ConfigMap {release.config_map}'s gateway.toml registers this sidecar"
              if same and there else
              f"ConfigMap {release.config_map}'s gateway.toml does not register this sidecar "
              "as it was installed")
    else:
        found("registration", "fail", f"Secret {settings_name(release.fullname)} holds no "
                                      "registration digest: run `up --kubernetes` again")
    found("credential", "ok" if settings.get("COGNEXUS_API_KEY") else "fail",
          f"Secret {settings_name(release.fullname)} holds the gateway's credential"
          if settings.get("COGNEXUS_API_KEY") else
          f"Secret {settings_name(release.fullname)} holds no credential")

    containers = _containers(host, target)
    if containers.get("sidecar") == "absent":
        found("sidecar", "fail", "the gateway's pod has no ArtzAIn sidecar, so the gateway does "
                                 "not start: a helm upgrade without artzain's post-renderer? See "
                                 "`artzain connect openshell status --kubernetes` "
                                 "(helm_post_renderer), or run `up --kubernetes` again")
    else:
        found("sidecar", "ok" if containers.get("sidecar") == "ready" else "fail",
              f"the {SIDECAR} container is {containers.get('sidecar')}")
    found("gateway", "ok" if containers.get("gateway") == "ready" else "fail",
          f"the {GATEWAY_CONTAINER} container is {containers.get('gateway')}")
    if containers.get("sidecar") != "ready" or not containers.get("pod"):
        return answer()
    pod = str(containers["pod"])

    done = _kubectl(host, target, "exec", pod, "-c", SIDECAR, "--", "python", "-c", _SOCKET,
                    timeout=60)
    parts = (done.stdout or "").split()
    if done.returncode != 0 or len(parts) != 5:
        found("socket", "fail", f"{SOCKET} is missing: the sidecar is not serving the gateway")
    else:
        problems = []
        if parts[0] != "True":
            problems.append("it is not a socket")
        if parts[1] != "0o600":
            problems.append(f"it is {parts[1]}, so other users can call the interceptor")
        if parts[3] != "0o700":
            problems.append(f"its folder is {parts[3]}")
        if parts[2] != str(release.uid) or parts[4] != str(release.uid):
            problems.append("it is not the gateway's user's")
        found("socket", "fail" if problems else "ok",
              f"{SOCKET}: " + ("; ".join(problems) if problems else
                               "the gateway's user's alone, in a folder of theirs alone"))
    done = InSidecar(host, target, pod).run("openshell", "status", "-o", "json")
    found("cli", "ok" if done.returncode == 0 else "fail",
          "the openshell CLI in the sidecar reaches the gateway" if done.returncode == 0 else
          f"the openshell CLI in the sidecar cannot reach the gateway: {_said(done)}")
    said = reports(host, target, pod)
    if not isinstance(said, dict):
        found("reports", "fail", "the sidecar did not say what it reported")
    else:
        failed = [w for w in ("heartbeat", "inventory") if said.get(w) == "failed"]
        waiting = [w for w in ("heartbeat", "inventory") if said.get(w) not in ("ok", "failed")]
        if failed:
            found("reports", "fail", f"the engine did not take the last {' or '.join(failed)}")
        elif waiting:
            found("reports", "warn", f"the {' and the '.join(waiting)} not yet taken by the "
                                     "engine")
        elif said.get("partial"):
            found("reports", "warn", "the last inventory was not every sandbox")
        else:
            found("reports", "ok", "the engine took the last heartbeat and inventory")
    return answer()


def rotate_key(host: Any, target: Target, *, out: Any = print) -> Dict[str, Any]:
    """Swap the gateway's credential: mint the next one with the live one,
    put it in the settings Secret, restart the pod, and once the engine has
    taken a heartbeat sent with it, retire the old. If it does not, the
    Secret goes back to the old credential, which takes the new one back."""
    from artzain.openshell import connect

    data = connect.Record.load(record_path(host, target)).data
    if not data.get("connected") or not data.get("gateway_id"):
        raise _refused("this release's gateway is not connected: run `artzain connect openshell "
                       "up --kubernetes`")
    release = find(host, target)
    settings = _settings(host, target, release.fullname)
    old = settings.get("COGNEXUS_API_KEY") or ""
    if not old.startswith(connect.CREDENTIAL_PREFIX):
        raise _refused(f"Secret {settings_name(release.fullname)} holds no gateway credential")
    gateway_id = str(data["gateway_id"])
    route = (str(data.get("engine") or connect.DEFAULT_ENGINE).rstrip("/")
             + f"/api/v1/openshell/gateways/{gateway_id}/keys")
    proxy = settings.get("OPENSHELL_SIDECAR_PROXY", "")

    def call(tail: str, credential: str) -> Any:
        try:
            return host.post_json(route + tail, headers={"X-Api-Key": credential}, body={},
                                  proxy=proxy, ca_bundle=str(data.get("ca_bundle") or ""))
        except Exception as exc:  # noqa: BLE001 - said without the credential
            raise _refused(f"the engine could not be reached ({type(exc).__name__})") from None

    def refused(status_code: int) -> Exception:
        return _refused(connect._ROTATE_REFUSALS.get(status_code,
                                                     f"the engine refused (HTTP {status_code})"))

    status_code, _answer = call("/retire-others", old)
    if status_code != 200:
        raise refused(status_code)
    status_code, answer = call("", old)
    if status_code != 200:
        raise refused(status_code)
    new = answer.get("credential") if isinstance(answer, dict) else None
    if (not isinstance(new, str) or not new.startswith(connect.CREDENTIAL_PREFIX)
            or connect._UNSAFE.search(new) or len(new) > 256 or new == old):
        call("/retire-others", old)
        raise _refused("the engine's answer holds no gateway credential")

    def restarted_with(credential: str) -> bool:
        _apply_secret(host, target, release.fullname, {**settings, "COGNEXUS_API_KEY": credential})
        _kubectl(host, target, "rollout", "restart",
                 f"{release.kind.lower()}/{release.fullname}", timeout=60)
        _rolled_out(host, release)
        seen: Dict[str, Any] = {}

        def heard() -> bool:
            try:
                seen["r"] = reports(host, target, _pod(host, target))
            except Exception:  # noqa: BLE001 - the pod is still starting
                return False
            return isinstance(seen["r"], dict) and seen["r"].get("heartbeat") in ("ok", "failed")

        _wait(host, REPORTS_WAIT_SECONDS, heard)
        return isinstance(seen.get("r"), dict) and seen["r"].get("heartbeat") == "ok"

    if not restarted_with(new):
        restarted_with(old)
        call("/retire-others", old)
        raise _refused("the engine did not take the sidecar's heartbeat with the new credential: "
                       "the Secret is back on the old credential, and the new one is revoked. "
                       "See `artzain connect openshell doctor --kubernetes`")
    status_code, _answer = call("/retire-others", new)
    retired = status_code == 200
    connect._say(out, f"gateway {gateway_id}: the credential is rotated; the sidecar uses the new "
                      "one" + (", and the old one is revoked" if retired else
                               f". The engine did not revoke the old one (HTTP {status_code}): "
                               "run rotate-key again"))
    return {"gateway_id": gateway_id, "rotated": True, "old_key_retired": retired}


def render_arguments(parser: Any) -> None:
    """The post-renderer's options, as :meth:`Render.args` gives them."""
    for name in ("--kind", "--release", "--fullname", "--image"):
        parser.add_argument(name, required=True)
    for name in ("--uid", "--gid", "--port"):
        parser.add_argument(name, type=int, required=True)
    parser.add_argument("--gateway-id", default="")
    parser.add_argument("--jwt-secret", default="")
    parser.add_argument("--client-tls", default=CLIENT_TLS)
    parser.add_argument("--sidecar-port", type=int, default=8088)
    parser.add_argument("--ca-bundle-configmap", default="")


def render_of(args: Any) -> Render:
    """The :class:`Render` the post-renderer's options name."""
    return Render(kind=args.kind, release=args.release, fullname=args.fullname,
                  image=args.image, uid=args.uid, gid=args.gid, port=args.port,
                  gateway_id=args.gateway_id, jwt_secret=args.jwt_secret,
                  client_tls=args.client_tls, sidecar_port=args.sidecar_port,
                  ca_bundle=args.ca_bundle_configmap)


def render_stdio(render: Render, stdin: Any, stdout: Any) -> None:
    """``artzain openshell kube-render``: Helm's post-renderer, manifests in
    on *stdin* and out on *stdout*."""
    import subprocess

    def run(command: List[str]) -> str:
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=120,
                                  check=False)
        except FileNotFoundError:
            raise _refused("kubectl is not on PATH: the post-renderer runs `kubectl kustomize`, "
                           "and helm runs it with helm's own PATH") from None
        if done.returncode != 0:
            raise _refused(f"kubectl kustomize failed: {(done.stderr or '').strip()[-300:]}")
        return done.stdout

    stdout.write(post_render(stdin.read(), render, run))


__all__ = ["CA_BUNDLE", "CA_KEY", "CHART", "CHART_NAME", "CLI", "InSidecar", "Release", "Render", "SIDECAR", "SOCKET",
           "Target", "bound", "ca_bundle_text", "ca_configmap", "ca_manifest", "doctor", "endpoint", "find", "helm_args", "kustomization",
           "mtls_folder", "ours", "patch", "post_render", "record_path", "remove", "render_arguments",
           "render_of", "render_stdio",
           "reports", "rotate_key", "secret_manifest", "settings_name", "sidecar", "status",
           "target", "up", "user_values", "without"]
