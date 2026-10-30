from fastapi.testclient import TestClient

from security.hashing import hash_directory
from server.main import create_app

ADMIN = {"X-Admin-Secret": "test-admin-secret-123456"}  # matches tests/conftest.py


def issue(client, days=30, licensee="tester"):
    r = client.post("/api/licenses/generate", json={"licensee": licensee, "valid_days": days}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------- health & public
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["database"] == "ok" and "key_fingerprint" in body


def test_public_key_does_not_leak_private_key(client, settings):
    r = client.get("/api/public-key")
    assert r.status_code == 200
    assert settings.private_key_b64 not in r.text
    assert r.json()["algorithm"] == "Ed25519"


def test_dashboard_served(client):
    r = client.get("/dashboard/")
    assert r.status_code == 200 and "PHANTOM" in r.text


# ---------------------------------------------------------------- authentication
def test_generate_requires_admin_header(client):
    r = client.post("/api/licenses/generate", json={"licensee": "x"})
    assert r.status_code == 401 and r.json()["error"] == "UNAUTHORIZED"


def test_generate_rejects_wrong_secret(client):
    r = client.post("/api/licenses/generate", json={"licensee": "x"}, headers={"X-Admin-Secret": "nope"})
    assert r.status_code == 403
    events = client.get("/api/events", params={"category": "SECURITY"}).json()["events"]
    assert any(e["outcome"] == "auth_failure" for e in events)


def test_revoke_and_list_require_admin(client):
    assert client.post("/api/licenses/revoke", json={"license_id": "LIC-X"}).status_code == 401
    assert client.get("/api/licenses").status_code == 401


def test_generate_never_returns_private_key(client, settings):
    r = client.post("/api/licenses/generate", json={"licensee": "x"}, headers=ADMIN)
    assert settings.private_key_b64 not in r.text


# ---------------------------------------------------------------- license flow
def test_generate_and_verify_valid(client):
    lic = issue(client)
    r = client.post("/api/licenses/verify", json={"license_key": lic["license_key"], "client_id": "pytest"})
    assert r.status_code == 200 and r.json()["valid"] is True


def test_verify_invalid_signature(client):
    key = issue(client)["license_key"]
    forged = key[:-4] + ("AAAA" if not key.endswith("AAAA") else "BBBB")
    r = client.post("/api/licenses/verify", json={"license_key": forged})
    assert r.status_code in (400, 403) and r.json()["valid"] is False


def test_verify_garbage_is_400(client):
    r = client.post("/api/licenses/verify", json={"license_key": "hello"})
    assert r.status_code == 400 and r.json()["code"] == "MALFORMED"


def test_verify_expired(client):
    key = issue(client, days=-1)["license_key"]
    r = client.post("/api/licenses/verify", json={"license_key": key})
    assert r.status_code == 403 and r.json()["code"] == "EXPIRED"


def test_revoke_flow(client):
    lic = issue(client)
    lid = lic["license"]["license_id"]
    r = client.post("/api/licenses/revoke", json={"license_id": lid, "reason": "test"}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["license"]["status"] == "revoked"
    assert client.post("/api/licenses/revoke", json={"license_id": lid}, headers=ADMIN).status_code == 409
    assert client.post("/api/licenses/revoke", json={"license_id": "LIC-NOPE"}, headers=ADMIN).status_code == 404
    r = client.post("/api/licenses/verify", json={"license_key": lic["license_key"]})
    assert r.status_code == 403 and r.json()["code"] == "REVOKED"


def test_validation_errors_are_structured(client):
    r = client.post("/api/licenses/generate", json={"licensee": "", "valid_days": 99999}, headers=ADMIN)
    assert r.status_code == 422 and r.json()["error"] == "VALIDATION_ERROR"


# ---------------------------------------------------------------- integrity
def test_integrity_workspace_and_simulation(client):
    assert client.post("/api/integrity/verify").json()["status"] == "PASS"
    assert client.post("/api/integrity/simulate", json={"action": "tamper"}).status_code == 401
    assert client.post("/api/integrity/simulate", json={"action": "tamper"}, headers=ADMIN).status_code == 200
    report = client.post("/api/integrity/verify").json()
    assert report["status"] == "FAIL" and report["summary"]["modified"] == 1
    client.post("/api/integrity/simulate", json={"action": "restore"}, headers=ADMIN)
    assert client.post("/api/integrity/verify").json()["status"] == "PASS"


def test_integrity_client_report(client, settings):
    hashes = hash_directory(settings.sample_dir)
    assert client.post("/api/integrity/verify", json={"client_id": "c1", "files": hashes}).json()["status"] == "PASS"
    first = next(iter(hashes))
    hashes[first] = "0" * 64
    assert client.post("/api/integrity/verify", json={"client_id": "c1", "files": hashes}).json()["status"] == "FAIL"


def test_integrity_rejects_bad_hash(client):
    r = client.post("/api/integrity/verify", json={"files": {"a": "xyz"}})
    assert r.status_code == 422


# ---------------------------------------------------------------- monitoring
def test_stats_and_events(client):
    issue(client)
    client.post("/api/licenses/verify", json={"license_key": "junk"})
    stats = client.get("/api/stats").json()
    assert stats["licenses"]["active"] == 1
    assert stats["verifications"]["failed"] >= 1
    assert len(stats["timeline"]) == 30
    events = client.get("/api/events", params={"limit": 5}).json()["events"]
    assert 0 < len(events) <= 5


def test_rate_limiting(settings):
    settings.rate_limit_per_minute = 3
    with TestClient(create_app(settings)) as c:
        codes = [c.post("/api/licenses/verify", json={"license_key": "x"}).status_code for _ in range(5)]
    assert codes[-1] == 429


def test_production_requires_secrets(tmp_path):
    from server.config import Settings
    import pytest
    s = Settings(app_env="production", data_dir=tmp_path, admin_secret="")
    with pytest.raises(RuntimeError):
        s.load_signing_key()
    with pytest.raises(RuntimeError):
        s.resolve_admin_secret()
