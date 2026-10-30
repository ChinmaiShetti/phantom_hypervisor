from pathlib import Path

import pytest

from security.hashing import compare_hashes, hash_directory, sha256_file
from security.signing import generate_private_key, public_key_b64
from security.verification import load_public_key, verify_document
from server.integrity import IntegrityService

SAMPLE = Path(__file__).resolve().parent.parent / "sample_app"


@pytest.fixture
def service(tmp_path):
    return IntegrityService(SAMPLE, tmp_path / "workspace", generate_private_key(), "PHANTOM-DEMO")


def test_sha256_known_value(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"abc")
    assert sha256_file(f) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_unmodified_sample_passes(service):
    report = service.verify_workspace()
    assert report["status"] == "PASS"
    assert report["summary"]["ok"] == len(service.trusted) >= 1


def test_modified_sample_detected(service):
    service.tamper("protected_sample.txt")
    report = service.verify_workspace()
    assert report["status"] == "FAIL"
    entry = next(f for f in report["files"] if f["path"] == "protected_sample.txt")
    assert entry["status"] == "MODIFIED" and entry["expected"] != entry["actual"]


def test_missing_sample_detected(service):
    service.delete("protected_sample.txt")
    report = service.verify_workspace()
    assert report["status"] == "FAIL" and report["summary"]["missing"] == 1


def test_injected_file_detected(service):
    service.inject()
    assert service.verify_workspace()["summary"]["unexpected"] == 1


def test_restore_recovers(service):
    service.tamper()
    service.restore()
    assert service.verify_workspace()["status"] == "PASS"


def test_unknown_file_rejected(service):
    with pytest.raises(ValueError):
        service.tamper("../../etc/passwd")


def test_manifest_is_signed(tmp_path):
    key = generate_private_key()
    svc = IntegrityService(SAMPLE, tmp_path / "ws", key, "PHANTOM-DEMO")
    payload = verify_document(load_public_key(public_key_b64(key)), svc.signed_manifest)
    assert payload["files"] == hash_directory(SAMPLE)


def test_tamper_works_when_pristine_files_are_read_only(tmp_path):
    """Docker images make /app read-only; the workspace copy must still be writable."""
    import shutil
    import stat
    pristine = tmp_path / "pristine"
    shutil.copytree(SAMPLE, pristine)
    for p in pristine.rglob("*"):
        p.chmod(stat.S_IREAD)
    svc = IntegrityService(pristine, tmp_path / "ws", generate_private_key(), "PHANTOM-DEMO")
    svc.tamper()
    assert svc.verify_workspace()["status"] == "FAIL"
    svc.restore()
    assert svc.verify_workspace()["status"] == "PASS"
    for p in pristine.rglob("*"):
        p.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_compare_empty_is_fail():
    assert compare_hashes({}, {})["status"] == "FAIL"
