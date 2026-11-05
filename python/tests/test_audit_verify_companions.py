"""Readable companions in the bundle (audit linkage plan, WP2).

An export ships ``decisions.csv`` and ``README.md`` beside the sealed files,
and its signed manifest commits each by the SHA-256 of its bytes under
``companions``. The verifier checks every file the manifest lists: present,
and hashing to the committed value. A bundle whose manifest lists none
verifies as before, and a release from before this one ignores the map.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from unittest import mock

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

#: A CSV as the server writes it: RFC 4180 records end CRLF, and a cell may
#: hold a line break of its own.
_CSV = 'seq,target\r\n1,"crm:a,""b""\nc"\r\n2,Zoë\r\n'.encode("utf-8")
_README = "# Evidence bundle\n\nVerify it with `artzain audit verify`.\n".encode("utf-8")


def _manifest(signer, d: Path, companions) -> dict:
    """The signed manifest of ``_build_bundle``'s five leaves, with *companions*."""
    manifest = _signed_manifest(signer, 1, 5, 5, seal_count=1, leaves=_read_leaves(d))
    body = {k: v for k, v in manifest.items() if k not in ("sig", "signer_key_id")}
    if companions is not None:
        body["companions"] = companions
    signed = hashlib.sha256(av._canonical(body)).hexdigest()
    return {**body, "sig": signer.sign(signed.encode("ascii")), "signer_key_id": signer.key_id}


def _companions_bundle(tmp: Path, signer, *, files=None, companions=None) -> Path:
    """A clean bundle carrying the two companions, committed by a signed manifest."""
    d = _build_bundle(tmp, signer)
    files = {"decisions.csv": _CSV, "README.md": _README} if files is None else files
    for name, data in files.items():
        (d / name).write_bytes(data)
    if companions is None:
        companions = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    (d / "manifest.json").write_text(json.dumps(_manifest(signer, d, companions)),
                                     encoding="utf-8")
    return d


def _zipped(d: Path, tmp: Path) -> Path:
    bundle = tmp / "bundle.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        for path in sorted(d.iterdir()):
            zf.write(path, path.name)
    return bundle


@pytest.fixture()
def signer():
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography not installed")
    return _Signer()


# -- the recipe ------------------------------------------------------------------------


def test_the_digest_is_sha256_over_the_files_bytes():
    assert av._companion_digest(_CSV) == hashlib.sha256(_CSV).hexdigest()
    assert av._companion_digest(b"") == hashlib.sha256(b"").hexdigest()


# -- what verifies -----------------------------------------------------------------------


@requires_crypto
def test_a_bundle_with_its_companions_verifies(tmp_path, signer):
    result = verify_bundle(_companions_bundle(tmp_path, signer))

    assert result.ok, (result.error, result.warnings)
    assert result.attestation == "SELF-ATTESTED"


@requires_crypto
def test_a_zipped_bundle_with_its_companions_verifies(tmp_path, signer):
    d = _companions_bundle(tmp_path, signer)

    result = verify_bundle(_zipped(d, tmp_path))

    assert result.ok, (result.error, result.warnings)


@requires_crypto
def test_the_bytes_are_hashed_as_they_are_with_their_line_ends(tmp_path, signer):
    """A directory bundle is read as bytes: reading it as text would turn the
    CSV's CRLF into LF on the way in, and a genuine bundle would fail."""
    d = _companions_bundle(tmp_path, signer)
    assert b"\r\n" in (d / "decisions.csv").read_bytes()

    assert verify_bundle(d).ok


@requires_crypto
def test_a_bundle_from_before_companions_verifies_as_before(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    (d / "manifest.json").write_text(json.dumps(_manifest(signer, d, None)), encoding="utf-8")
    plain = verify_bundle(d)
    # Files the manifest does not list are not read.
    (d / "decisions.csv").write_bytes(b"anything")

    result = verify_bundle(d)

    assert plain.ok and result.ok
    assert result == plain


@requires_crypto
def test_an_empty_map_lists_nothing_to_check(tmp_path, signer):
    result = verify_bundle(_companions_bundle(tmp_path, signer, files={}, companions={}))

    assert result.ok, (result.error, result.warnings)


# -- what fails --------------------------------------------------------------------------


@requires_crypto
def test_an_altered_csv_fails(tmp_path, signer):
    d = _companions_bundle(tmp_path, signer)
    (d / "decisions.csv").write_bytes(_CSV.replace(b"Zo\xc3\xab", b"Zoe"))

    result = verify_bundle(d)

    assert not result.ok
    assert result.first_bad_seq is None
    assert result.error == "companion decisions.csv altered (digest mismatch)"


@requires_crypto
def test_a_csv_resaved_with_other_line_ends_fails(tmp_path, signer):
    d = _companions_bundle(tmp_path, signer)
    (d / "decisions.csv").write_bytes(_CSV.replace(b"\r\n", b"\n"))

    result = verify_bundle(d)

    assert result.error == "companion decisions.csv altered (digest mismatch)"


@requires_crypto
def test_a_removed_readme_fails(tmp_path, signer):
    d = _companions_bundle(tmp_path, signer)
    (d / "README.md").unlink()

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == "companion README.md missing"


@requires_crypto
def test_a_removed_companion_fails_in_a_zip(tmp_path, signer):
    d = _companions_bundle(tmp_path, signer)
    (d / "decisions.csv").unlink()

    result = verify_bundle(_zipped(d, tmp_path))

    assert result.error == "companion decisions.csv missing"


@requires_crypto
def test_a_digest_that_is_not_a_string_is_a_mismatch(tmp_path, signer):
    d = _companions_bundle(tmp_path, signer, companions={"README.md": 7})

    assert verify_bundle(d).error == "companion README.md altered (digest mismatch)"


@requires_crypto
@pytest.mark.parametrize("name", ["../manifest.json", "sub/README.md", "sub\\README.md",
                                  "README.md:stream", "C:README.md", ".", "..", "",
                                  "README\x00.md", "Réadme.md", "‮README.md"])
def test_a_name_that_is_not_a_plain_file_name_fails_without_being_read(tmp_path, signer, name):
    d = _companions_bundle(tmp_path, signer,
                           files={"decisions.csv": _CSV},
                           companions={"decisions.csv": hashlib.sha256(_CSV).hexdigest(),
                                       name: hashlib.sha256(b"x").hexdigest()})

    with mock.patch.object(av, "_companion_file_digest", wraps=av._companion_file_digest) as reads:
        result = verify_bundle(d)

    assert not result.ok
    assert result.error == f"companion {ascii(name)} is not a plain file name"
    assert [call.args[1] for call in reads.call_args_list] == ["decisions.csv"]


@requires_crypto
@pytest.mark.parametrize("companions", [["README.md"], "README.md", 7, None])
def test_a_companions_value_that_is_not_a_map_fails(tmp_path, signer, companions):
    d = _build_bundle(tmp_path, signer)
    manifest = _manifest(signer, d, None)
    body = {k: v for k, v in manifest.items() if k not in ("sig", "signer_key_id")}
    body["companions"] = companions
    signed = hashlib.sha256(av._canonical(body)).hexdigest()
    (d / "manifest.json").write_text(json.dumps(
        {**body, "sig": signer.sign(signed.encode("ascii")), "signer_key_id": signer.key_id}),
        encoding="utf-8")

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == "companions is not a map of file names to digests"


@requires_crypto
def test_without_cryptography_a_mismatch_says_the_signature_was_not_verified(tmp_path, signer):
    d = _companions_bundle(tmp_path, signer)
    (d / "README.md").write_bytes(b"edited")

    with mock.patch.object(av, "_load_public_keys", lambda keys: None):
        result = verify_bundle(d)

    assert not result.ok
    assert result.error == ("companion README.md altered (digest mismatch, "
                            "signature not verified)")


@requires_crypto
def test_the_companions_are_checked_after_the_record_set(tmp_path, signer):
    """A bundle whose leaf set no longer matches fails on that first: the
    companions describe the records, and are read only once those hold."""
    d = _companions_bundle(tmp_path, signer)
    leaves = (d / "leaves.jsonl").read_text(encoding="utf-8").splitlines()
    (d / "leaves.jsonl").write_text("\n".join(leaves[:-1]) + "\n", encoding="utf-8")
    (d / "README.md").unlink()

    result = verify_bundle(d)

    assert not result.ok
    assert "companion" not in (result.error or "")
