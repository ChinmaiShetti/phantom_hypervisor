"""License issuance and revocation. The only component that uses the private key."""
from __future__ import annotations

import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.signing import issue_license_token, key_fingerprint, public_key_b64
from security.verification import load_public_key
from server.database import Database


class LicenseManager:
    def __init__(self, db: Database, private_key: Ed25519PrivateKey, revoked_ids: set[str] | None = None):
        self.db = db
        self._private_key = private_key  # never serialised into any response
        self.public_key_b64 = public_key_b64(private_key)
        self.public_key = load_public_key(self.public_key_b64)
        self.fingerprint = key_fingerprint(self.public_key_b64)
        # Revocations supplied via env survive restarts of a stateless cloud instance.
        self.static_revocations = set(revoked_ids or ())

    def issue(self, product_id: str, licensee: str, valid_days: int, now: float | None = None) -> tuple[str, dict[str, Any]]:
        issued = int(time.time() if now is None else now)
        claims = {
            "license_id": f"LIC-{uuid.uuid4().hex[:12].upper()}",
            "product_id": product_id,
            "licensee": licensee,
            "issued_at": issued,
            "expires_at": issued + int(valid_days * 86400),
            "key_id": self.fingerprint,
        }
        token = issue_license_token(self._private_key, claims)
        self.db.insert_license(claims)
        return token, {**claims, "status": self.status_of(claims)}

    def revoke(self, license_id: str, reason: str) -> dict[str, Any] | None:
        record = self.db.get_license(license_id)
        if record is None:
            return None
        self.db.revoke_license(license_id, reason)
        return self.db.get_license(license_id)

    def is_revoked(self, license_id: str) -> bool:
        if license_id in self.static_revocations:
            return True
        record = self.db.get_license(license_id)
        return bool(record and record["status"] == "revoked")

    @staticmethod
    def status_of(record: dict[str, Any], now: float | None = None) -> str:
        now = time.time() if now is None else now
        if record.get("status") == "revoked":
            return "revoked"
        return "expired" if record["expires_at"] <= now else "active"

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        now = time.time()
        return [{**r, "status": self.status_of(r, now)} for r in self.db.list_licenses(limit)]
