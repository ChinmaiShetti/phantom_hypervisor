"""Online license validation: offline checks + server-side registry/revocation."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from security.verification import LicenseError, peek_claims, verify_license_offline
from server.license_manager import LicenseManager

# Machine code -> HTTP status for the /verify endpoint.
HTTP_STATUS = {
    "VALID": 200,
    "MALFORMED": 400,
    "BAD_SIGNATURE": 403,
    "EXPIRED": 403,
    "NOT_YET_VALID": 403,
    "PRODUCT_MISMATCH": 403,
    "REVOKED": 403,
    "UNKNOWN_LICENSE": 403,
}


@dataclass
class ValidationResult:
    valid: bool
    code: str
    message: str
    claims: dict[str, Any] | None

    @property
    def http_status(self) -> int:
        return HTTP_STATUS.get(self.code, 403)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "code": self.code,
            "message": self.message,
            "license": self.claims,
            "checked_at": time.time(),
        }


def validate_license(
    token: str,
    manager: LicenseManager,
    *,
    product_id: str | None = None,
    strict_registry: bool = False,
    now: float | None = None,
) -> ValidationResult:
    """Pipeline: format -> signature -> product -> time -> revocation -> registry."""
    try:
        claims = verify_license_offline(token, manager.public_key, product_id=product_id, now=now)
    except LicenseError as err:
        # For a forged token we still show what it *claimed*, clearly labelled unverified.
        shown = err.claims if err.code != "BAD_SIGNATURE" else {"unverified_claims": peek_claims(token)}
        return ValidationResult(False, err.code, err.message, shown)

    if manager.is_revoked(claims["license_id"]):
        return ValidationResult(False, "REVOKED", "License has been revoked by the license server.", claims)

    if manager.db.get_license(claims["license_id"]) is None:
        if strict_registry:
            return ValidationResult(False, "UNKNOWN_LICENSE", "License is signed correctly but not in the registry.", claims)
        # Stateless mode (e.g. Render free tier after a restart wiped SQLite):
        # a valid signature is proof the license was issued by us.
        return ValidationResult(True, "VALID", "License is valid (signature verified; not in local registry - stateless mode).", claims)

    return ValidationResult(True, "VALID", "License is valid.", claims)
