"""The framework profile folder, committed by the signed manifest (auditor
journey plan, WP 2.4).

An export with ``?profile=<name>`` adds a ``<name>/`` folder: the control
mapping, the bundle history, the promotions and retirements, the licence
position and the compliance summary. Its signed manifest now commits each
file by the SHA-256 of its bytes under ``profile_files``, so a file edited,
removed or added after export fails the bundle, as ``companions`` does for
``decisions.csv`` and ``README.md``. A bundle whose manifest has no
``profile_files`` (exported before this release) verifies as before and the
verifier says nothing about its folder.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

import artzain.audit_verify as av
from artzain.audit_verify import verify_bundle

from .test_audit_verify import (  # noqa: TID252 - the tamper matrix's own builders
    _HAVE_CRYPTO,
    _build_bundle,
    _read_leaves,
    _signed_manifest,
    _Signer,
)

requires_crypto = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

_PROFILE = "eu-ai-act"
_FILES = {
    f"{_PROFILE}/mapping.md": b"# EU AI Act mapping\n",
    f"{_PROFILE}/compliance-summary.json": b'{"profile": "eu-ai-act"}',
    f"{_PROFILE}/policy-bundles.jsonl": b'{"name": "eu-ai-act"}\n',
}
_UNSET = object()


def _digests(files):
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def _bundle(tmp: Path, signer, *, files=None, committed=_UNSET, profile=_PROFILE) -> Path:
    """``_build_bundle``'s five leaves, a profile folder holding *files*, and a
    signed manifest naming *profile* and committing *committed* (by default
    the digests of *files*; ``None`` leaves ``profile_files`` out)."""
    d = _build_bundle(tmp, signer)
    files = dict(_FILES) if files is None else files
    for name, data in files.items():
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        (d / name).write_bytes(data)
    manifest = _signed_manifest(signer, 1, 5, 5, seal_count=1, leaves=_read_leaves(d))
    body = {k: v for k, v in manifest.items() if k not in ("sig", "signer_key_id")}
    body["profile"] = profile
    if committed is _UNSET:
        committed = _digests(files)
    if committed is not None:
        body["profile_files"] = committed
    signed = hashlib.sha256(av._canonical(body)).hexdigest()
    (d / "manifest.json").write_text(json.dumps(
        {**body, "sig": signer.sign(signed.encode("ascii")), "signer_key_id": signer.key_id}), encoding="utf-8")
    return d


def _zipped(d: Path, tmp: Path) -> Path:
    bundle = tmp / "bundle.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        for path in sorted(p for p in d.rglob("*") if p.is_file()):
            zf.write(path, path.relative_to(d).as_posix())
    return bundle


@pytest.fixture()
def signer():
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography not installed")
    return _Signer()


# -- what verifies ---------------------------------------------------------------


@requires_crypto
def test_a_committed_profile_folder_verifies(tmp_path, signer):
    result = verify_bundle(_bundle(tmp_path, signer))

    assert result.ok, result.error


@requires_crypto
def test_a_zipped_committed_profile_folder_verifies(tmp_path, signer):
    result = verify_bundle(_zipped(_bundle(tmp_path, signer), tmp_path))

    assert result.ok, result.error


@requires_crypto
def test_a_bundle_from_before_profile_files_verifies_as_before(tmp_path, signer):
    result = verify_bundle(_bundle(tmp_path, signer, committed=None))

    assert result.ok, result.error
    assert not any("profile" in w for w in result.warnings), result.warnings


@requires_crypto
def test_a_bundle_without_a_profile_commits_an_empty_map(tmp_path, signer):
    result = verify_bundle(_bundle(tmp_path, signer, files={}, committed={}, profile=None))

    assert result.ok, result.error


# -- what fails ------------------------------------------------------------------


@requires_crypto
def test_an_edited_profile_file_fails(tmp_path, signer):
    d = _bundle(tmp_path, signer)
    (d / f"{_PROFILE}/mapping.md").write_bytes(b"# edited\n")

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == f"profile file {_PROFILE}/mapping.md altered (digest mismatch)"


@requires_crypto
def test_an_edited_profile_file_fails_in_a_zip(tmp_path, signer):
    d = _bundle(tmp_path, signer)
    (d / f"{_PROFILE}/compliance-summary.json").write_bytes(b'{"profile": "edited"}')

    result = verify_bundle(_zipped(d, tmp_path))

    assert not result.ok and "compliance-summary.json altered" in (result.error or "")


@requires_crypto
def test_a_removed_profile_file_fails(tmp_path, signer):
    d = _bundle(tmp_path, signer)
    (d / f"{_PROFILE}/policy-bundles.jsonl").unlink()

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == f"profile file {_PROFILE}/policy-bundles.jsonl missing"


@requires_crypto
def test_a_file_added_to_the_profile_folder_fails(tmp_path, signer):
    d = _bundle(tmp_path, signer)
    (d / f"{_PROFILE}/extra.json").write_bytes(b"{}")

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == f"profile file {_PROFILE}/extra.json is not committed by the manifest"


@requires_crypto
@pytest.mark.parametrize("name", ["README.md", "other/mapping.md", f"{_PROFILE}/../keys.json",
                                  f"{_PROFILE}/sub/deep.md", f"{_PROFILE}/"])
def test_a_name_outside_the_profile_folder_fails_without_being_read(tmp_path, signer, name):
    d = _bundle(tmp_path, signer, committed={**_digests(_FILES), name: "0" * 64})

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == f"profile file {ascii(name)} is not a file of the {_PROFILE}/ folder"


@requires_crypto
@pytest.mark.parametrize("committed", [[], "x", 7])
def test_a_profile_files_value_that_is_not_a_map_fails(tmp_path, signer, committed):
    result = verify_bundle(_bundle(tmp_path, signer, committed=committed))

    assert not result.ok
    assert result.error == "profile_files is not a map of file names to digests"


@requires_crypto
def test_profile_files_without_a_profile_fails(tmp_path, signer):
    result = verify_bundle(_bundle(tmp_path, signer, profile=None))

    assert not result.ok
    assert result.error == "profile_files is set but the manifest names no profile"


def test_the_digest_is_the_companions():
    data = b"# mapping\n"
    assert av._companion_digest(data) == hashlib.sha256(data).hexdigest()
