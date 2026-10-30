import time

import pytest

from security.signing import (
    b64url_decode,
    b64url_encode,
    canonical_json,
    generate_private_key,
    issue_license_token,
    public_key_b64,
    sign_document,
)
from security.verification import (
    LicenseError,
    load_public_key,
    verify_document,
    verify_license_offline,
)
from server.database import Database
from server.license_manager import LicenseManager
from server.validator import validate_license


@pytest.fixture
def key():
    return generate_private_key()


@pytest.fixture
def manager(tmp_path, key):
    return LicenseManager(Database(tmp_path / "t.db"), key)


def claims(**overrides):
    now = int(time.time())
    base = {"license_id": "LIC-TEST", "product_id": "PHANTOM-DEMO", "licensee": "alice",
            "issued_at": now, "expires_at": now + 3600}
    return {**base, **overrides}


# ---------------------------------------------------------------- signatures
def test_valid_signature_verifies(key):
    token = issue_license_token(key, claims())
    result = verify_license_offline(token, load_public_key(public_key_b64(key)))
    assert result["licensee"] == "alice"


def test_signature_from_other_key_rejected(key):
    token = issue_license_token(generate_private_key(), claims())
    with pytest.raises(LicenseError) as err:
        verify_license_offline(token, load_public_key(public_key_b64(key)))
    assert err.value.code == "BAD_SIGNATURE"


def test_tampered_payload_rejected(key):
    """Classic crack attempt: extend the expiry date but keep the old signature."""
    prefix, payload, sig = issue_license_token(key, claims()).split(".")
    forged = {**__import__("json").loads(b64url_decode(payload)), "expires_at": 4102444800}
    token = f"{prefix}.{b64url_encode(canonical_json(forged))}.{sig}"
    with pytest.raises(LicenseError) as err:
        verify_license_offline(token, load_public_key(public_key_b64(key)))
    assert err.value.code == "BAD_SIGNATURE"


@pytest.mark.parametrize("token", ["", "garbage", "PHM1.abc", "XXX1.a.b", "PHM1.!!!.???"])
def test_malformed_tokens_rejected(key, token):
    with pytest.raises(LicenseError) as err:
        verify_license_offline(token, load_public_key(public_key_b64(key)))
    assert err.value.code in {"MALFORMED", "BAD_SIGNATURE"}


def test_signed_document_roundtrip_and_tamper(key):
    signed = sign_document(key, {"files": {"a.txt": "00" * 32}})
    pub = load_public_key(public_key_b64(key))
    assert verify_document(pub, signed)["files"]["a.txt"] == "00" * 32
    signed["payload"]["files"]["a.txt"] = "11" * 32
    with pytest.raises(ValueError):
        verify_document(pub, signed)


# ---------------------------------------------------------------- license lifecycle
def test_valid_license(manager):
    token, record = manager.issue("PHANTOM-DEMO", "bob", 30)
    assert record["status"] == "active"
    result = validate_license(token, manager)
    assert result.valid and result.code == "VALID" and result.http_status == 200


def test_invalid_license(manager):
    result = validate_license("PHM1.not.valid", manager)
    assert not result.valid and result.code in {"MALFORMED", "BAD_SIGNATURE"}


def test_expired_license(manager):
    token, record = manager.issue("PHANTOM-DEMO", "carol", -1)
    assert record["status"] == "expired"
    result = validate_license(token, manager)
    assert not result.valid and result.code == "EXPIRED" and result.http_status == 403


def test_revoked_license(manager):
    token, record = manager.issue("PHANTOM-DEMO", "dave", 30)
    manager.revoke(record["license_id"], "chargeback")
    result = validate_license(token, manager)
    assert not result.valid and result.code == "REVOKED"


def test_static_env_revocation(tmp_path, key):
    mgr = LicenseManager(Database(tmp_path / "s.db"), key)
    token, record = mgr.issue("PHANTOM-DEMO", "erin", 30)
    mgr.static_revocations.add(record["license_id"])
    assert validate_license(token, mgr).code == "REVOKED"


def test_product_mismatch(manager):
    token, _ = manager.issue("OTHER-PRODUCT", "frank", 30)
    assert validate_license(token, manager, product_id="PHANTOM-DEMO").code == "PRODUCT_MISMATCH"


def test_stateless_vs_strict_registry(tmp_path, key, manager):
    """A signed license unknown to a fresh database (e.g. Render restart) is accepted
    in stateless mode and rejected in strict mode."""
    token, _ = manager.issue("PHANTOM-DEMO", "gina", 30)
    fresh = LicenseManager(Database(tmp_path / "fresh.db"), key)
    assert validate_license(token, fresh).valid
    assert validate_license(token, fresh, strict_registry=True).code == "UNKNOWN_LICENSE"
