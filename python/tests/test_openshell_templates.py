"""What ``artzain connect openshell up`` writes, for every option it can be
given, and the invariants each rendering holds (Option C plan, S4.2 and §6).

``up`` renders on the operator's host. :mod:`artzain.openshell.templates`
renders the same files with the same functions for a stand-in host, so that:

* a golden file per combination pins what ``up`` writes;
* every rendering holds the plan's §6 invariants (outbound only, fail closed,
  the credential in one private file, removable byte for byte, ...);
* the conformance run puts each distinct ``gateway.toml`` through the real
  gateway's ``config preflight`` (S1.4 f);
* the renderings are what ``up`` writes, file for file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from artzain.openshell import connect, registration, templates

needs_tomllib = pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML")
GOLDEN = Path(__file__).resolve().parent / "golden" / "openshell-connect"
REGENERATE = "python -m artzain.openshell.templates write tests/golden/openshell-connect"
DEFAULT = next(c for c in templates.COMBINATIONS
               if c.interceptor_timeout_ms == 1500 and c.base == "operator" and not c.telemetry)


# ---------------------------------------------------------------------------
# The grid
# ---------------------------------------------------------------------------


def test_every_combination_is_a_configuration_up_accepts():
    for combo in templates.COMBINATIONS:
        parsed = connect.parse_config(combo.config)
        assert (parsed.interceptor_timeout_ms, parsed.decide_timeout_ms, parsed.telemetry) == (
            combo.interceptor_timeout_ms, combo.decide_timeout_ms, combo.telemetry)


def test_the_grid_takes_each_bound_and_each_choice():
    combos = templates.COMBINATIONS
    timeouts = {(c.interceptor_timeout_ms, c.decide_timeout_ms) for c in combos}
    # The decide timeout is 50 ms at least and below the interceptor's, so
    # the smallest interceptor timeout a configuration can carry is 51 ms.
    assert timeouts == {(51, 50), (1500, 1200),
                        (registration.TIMEOUT_MS_MAX, 30_000)}
    assert {c.telemetry for c in combos} == {False, True}
    assert {c.proxy for c in combos} == {False, True}
    assert {c.base for c in combos} == set(templates.BASES) == {"none", "minimal", "operator"}
    assert len(combos) == len({c.name for c in combos}) == 3 * 3 * 2
    every = {(c.interceptor_timeout_ms, c.base, c.telemetry) for c in combos}
    assert len(every) == 18, "every timeout with every file and each telemetry choice"


# ---------------------------------------------------------------------------
# Golden files
# ---------------------------------------------------------------------------


@needs_tomllib
@pytest.mark.parametrize("combo", templates.COMBINATIONS, ids=lambda c: c.name)
def test_each_rendering_is_its_golden_file(combo):
    golden = GOLDEN / f"{combo.name}.txt"
    assert golden.is_file(), f"no golden file for {combo.name}: {REGENERATE}"
    wanted = golden.read_bytes().decode("utf-8").replace("\r\n", "\n")
    assert templates.as_text(templates.render(combo)) == wanted, (
        f"what `up` writes for {combo.name} changed; if that is meant, {REGENERATE}")


def test_no_golden_file_is_left_over():
    assert sorted(p.stem for p in GOLDEN.glob("*.txt")) == sorted(
        c.name for c in templates.COMBINATIONS)


@needs_tomllib
def test_a_rendering_names_each_file_up_writes():
    files = templates.render(DEFAULT)
    assert list(files) == [
        ".config/openshell/gateway.toml",
        ".config/openshell/gateway.env",
        ".config/artzain/openshell/sidecar.env",
        f".config/systemd/user/{connect.SIDECAR_UNIT}",
        f".config/systemd/user/{connect.GATEWAY_UNIT}.d/{connect.DROPIN}",
    ]
    text = templates.as_text(files)
    assert text.count("==> ") == 5 and text.endswith("\n")


@needs_tomllib
def test_the_distinct_gateway_tomls_are_one_per_timeout_and_file():
    tomls = templates.gateway_tomls()
    assert len(tomls) == 3 * 3
    for name, text in tomls.items():
        assert connect.BLOCK_BEGIN in text and "[openshell]" in text, name


@needs_tomllib
def test_a_gateway_toml_that_telemetry_changed_is_not_preflighted_once(monkeypatch):
    """Telemetry goes to gateway.env. Were it to change gateway.toml, one
    preflight per timeout and file would miss a rendering."""
    real = templates.render

    def render(combo):
        files = real(combo)
        if combo.telemetry:
            files[".config/openshell/gateway.toml"] += "# telemetry\n"
        return files

    monkeypatch.setattr(templates, "render", render)
    with pytest.raises(ValueError):
        templates.gateway_tomls()


@needs_tomllib
def test_the_command_writes_the_golden_files_and_the_gateway_tomls(tmp_path, capsys):
    assert templates.main(["write", str(tmp_path / "golden")]) == 0
    assert sorted(p.name for p in (tmp_path / "golden").iterdir()) == sorted(
        f"{c.name}.txt" for c in templates.COMBINATIONS)
    assert templates.main(["gateway-tomls", str(tmp_path / "tomls")]) == 0
    written = {p.stem: p.read_bytes().decode("utf-8") for p in (tmp_path / "tomls").iterdir()}
    assert written == templates.gateway_tomls()
    assert all(p.suffix == ".toml" for p in (tmp_path / "tomls").iterdir())
    capsys.readouterr()
    assert templates.main(["nothing"]) == 2


# ---------------------------------------------------------------------------
# The invariants
# ---------------------------------------------------------------------------


@needs_tomllib
@pytest.mark.parametrize("combo", templates.COMBINATIONS, ids=lambda c: c.name)
def test_every_rendering_holds_the_invariants(combo):
    assert templates.invariants(templates.render(combo), combo.base_text, config=combo.parsed,
                                credential=templates.CREDENTIAL) == []


def _broken(edit):
    files = templates.render(DEFAULT)
    edit(files)
    return templates.invariants(files, DEFAULT.base_text, config=DEFAULT.parsed,
                                credential=templates.CREDENTIAL)


TOML = ".config/openshell/gateway.toml"
ENV = ".config/openshell/gateway.env"
SIDECAR_ENV = ".config/artzain/openshell/sidecar.env"
UNIT = f".config/systemd/user/{connect.SIDECAR_UNIT}"
DROP_IN = f".config/systemd/user/{connect.GATEWAY_UNIT}.d/{connect.DROPIN}"


def _swap(name, old, new, count=1):
    def edit(files):
        assert files[name].count(old) >= count, (name, old)
        files[name] = files[name].replace(old, new, count)
    return edit


def _swap_last(name, old, new):
    """In the managed block, which comes after anything of the operator's."""
    def edit(files):
        head, found, tail = files[name].rpartition(old)
        assert found, (name, old)
        files[name] = head + new + tail
    return edit


@needs_tomllib
@pytest.mark.parametrize("edit, says", [
    (_swap(TOML, 'failure_policy = "fail_closed"', 'failure_policy = "fail_open"'),
     "fails closed"),
    (_swap(TOML, "unix:///run/user/1000/artzain/openshell.sock", "http://10.0.0.1:9", 2),
     "Unix socket"),
    (_swap(TOML, "unix:///run/user/1000/artzain/openshell.sock",
           "unix:///run/user/1000/other.sock", 2), "the sidecar's socket"),
    (_swap_last(TOML, 'phases = ["post_commit"]', 'phases = ["validate"]'), "after the commit"),
    (_swap(TOML, 'timeout        = "1500ms"', 'timeout        = "1499ms"'), "timeout"),
    (_swap(TOML, 'name           = "artzain-observe"', 'name           = "artzain-watch"'),
     "exactly once"),
    (_swap(TOML, "version = 2", "version = 3"), "version = 2"),
    (_swap(TOML, connect.BLOCK_END, '[[openshell.gateway.interceptors]]\nname = "artzain"\n'
           + connect.BLOCK_END), "exactly once"),
    (_swap(TOML, 'log_level = "info"', 'log_level = "debug"'), "byte for byte"),
    (_swap(TOML, connect.BLOCK_END, "# the end"), "taken out"),
    (_swap(ENV, "OPENSHELL_TELEMETRY_ENABLED=false", "OPENSHELL_TELEMETRY_ENABLED=true"),
     "telemetry"),
    (_swap(SIDECAR_ENV, 'OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS="1200"',
           'OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS="1500"'), "below the interceptor"),
    (_swap(SIDECAR_ENV, 'OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS="1200"',
           'OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS="1100"'), "the approved one"),
    (_swap(SIDECAR_ENV, f'COGNEXUS_API_KEY="{templates.CREDENTIAL}"',
           'COGNEXUS_API_KEY="cnxg_another"'), "do not hold the gateway's credential"),
    (_swap(SIDECAR_ENV, 'OPENSHELL_SIDECAR_HOST="127.0.0.1"', 'OPENSHELL_SIDECAR_HOST="0.0.0.0"'),
     "loopback"),
    (_swap(SIDECAR_ENV, 'OPENSHELL_GATEWAY_ID=', 'ARTZAIN_AGENT_DID="did:x"\nOPENSHELL_GATEWAY_ID='),
     "decides as"),
    (_swap(TOML, "[openshell]\nversion = 2", "[openshell\nversion = 2"), "is not TOML"),
    (_swap(ENV, "# >>>", "OPENSHELL_EXTRA=1\n# >>>"), "one removable block"),
    (_swap(UNIT, "Type=notify\n", "Type=simple\n"), "Type=notify"),
    (_swap(UNIT, "EnvironmentFile=", "EnvironmentFile=/tmp/elsewhere.env\n# was "),
     "read its settings from sidecar.env"),
    (_swap(UNIT, "UMask=0077\n", ""), "UMask=0077"),
    (_swap(UNIT, "NoNewPrivileges=yes\n", ""), "NoNewPrivileges=yes"),
    (_swap(UNIT, "[Service]\n", f"[Service]\nEnvironment=COGNEXUS_API_KEY={templates.CREDENTIAL}\n"),
     "credential"),
    (_swap(DROP_IN, f"Requires={connect.SIDECAR_UNIT}\n", ""), "Requires="),
    (_swap(DROP_IN, f"After={connect.SIDECAR_UNIT}\n", ""), "After="),
    (_swap(UNIT, "# Written by", "# Certified by NVIDIA. Written by"), "NVIDIA"),
])
def test_a_broken_rendering_is_named(edit, says):
    found = _broken(edit)
    assert any(says in problem for problem in found), found


@needs_tomllib
def test_a_missing_file_is_named():
    def edit(files):
        del files[DROP_IN]
    assert any("is not written" in problem for problem in _broken(edit))


@needs_tomllib
def test_the_one_allowed_nvidia_phrase_is_allowed():
    def edit(files):
        files[UNIT] = files[UNIT].replace("# Written by", "# Works with NVIDIA OpenShell. Written by")
    assert _broken(edit) == []


# ---------------------------------------------------------------------------
# The renderings are what up writes
# ---------------------------------------------------------------------------


def _connect_harness():
    """The deb gateway ``test_openshell_connect.py`` drives ``up`` against."""
    import importlib.util

    path = Path(__file__).with_name("test_openshell_connect.py")
    spec = importlib.util.spec_from_file_location("openshell_connect_harness", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@needs_tomllib
@pytest.mark.parametrize("base", ["none", "operator"])
@pytest.mark.parametrize("telemetry", [False, True])
def test_the_renderings_are_what_up_writes(tmp_path, base, telemetry):
    harness = _connect_harness()

    gateway = harness._Gateway(tmp_path, toml=templates.BASES[base])
    config = dict(harness.CONFIG, telemetry=telemetry)
    gateway.redeem = (200, {"gateway_id": harness.GATEWAY, "credential": harness.CREDENTIAL,
                            "agent_did": f"openshell:{harness.GATEWAY}",
                            "key_prefix": harness.CREDENTIAL[:12],
                            "config_digest": connect.config_digest(config), "config": config})
    connect.up(gateway.host(), token=harness.TOKEN, digest=connect.config_digest(config),
               engine="https://engine.example/", out=lambda _line: None,
               proxy="http://proxy.example:3128" if telemetry else "")
    files = templates.render_for(
        gateway.host(), connect.parse_config(config), toml_text=templates.BASES[base] or "",
        gateway_id=harness.GATEWAY, credential=harness.CREDENTIAL, port=connect.DEFAULT_PORT,
        proxy="http://proxy.example:3128" if telemetry else "", ca_bundle="")
    for name, text in files.items():
        written = (gateway.home / name).read_bytes().decode("utf-8")
        assert written == text, name
    assert templates.invariants(files, templates.BASES[base], config=connect.parse_config(config),
                                credential=harness.CREDENTIAL) == []
