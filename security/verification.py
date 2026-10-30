"""Signature and license-claim verification.

Everything here needs only the PUBLIC key, so the protected client can perform
offline verification without ever holding signing material.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from security.signing import TOKEN_PREFIX, b64url_decode, canonical_json

REQUIRED_CLAIMS = ("license_id", "product_id", "licensee", "issued_at", "expires_at")
CLOCK_SKEW_SECONDS = 60
MAX_TOKEN_LENGTH = 4096


class LicenseError(Exception):
    """A license failed validation. `code` is a stable machine-readable reason."""

    def __init__(self, code: str, message: str, claims: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.claims = claims


def load_public_key(b64_value: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(b64_value.strip(), validate=True)
    except Exception as exc:
        raise ValueError("Public key is not valid base64") from exc
    if len(raw) != 32:
        raise ValueError("Public key must decode to 32 bytes (raw Ed25519)")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_signature(public_key: Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def peek_claims(token: str) -> dict[str, Any] | None:
    """Decode claims WITHOUT verifying them. Only for display / logging."""
    try:
        return json.loads(b64url_decode(token.strip().split(".")[1]))
    except Exception:
        return None


def decode_license_token(token: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Check structure and signature; return the claims. Does NOT check expiry."""
    token = token.strip()
    if len(token) > MAX_TOKEN_LENGTH:
        raise LicenseError("MALFORMED", "License key is too long.")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise LicenseError("MALFORMED", "License key format is not recognised (expected PHM1.<payload>.<signature>).")
    try:
        payload_bytes = b64url_decode(parts[1])
        signature = b64url_decode(parts[2])
        claims = json.loads(payload_bytes)
    except Exception:
        raise LicenseError("MALFORMED", "License key could not be decoded.")
    if not isinstance(claims, dict):
        raise LicenseError("MALFORMED", "License payload must be a JSON object.")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    if not verify_signature(public_key, signing_input, signature):
        raise LicenseError(
            "BAD_SIGNATURE",
            "Digital signature verification failed: the license was forged, altered, or signed by a different key.",
            claims,
        )
    missing = [c for c in REQUIRED_CLAIMS if c not in claims]
    if missing:
        raise LicenseError("MALFORMED", f"License is missing claims: {', '.join(missing)}.", claims)
    return claims


def check_claims(claims: dict[str, Any], *, now: float | None = None, product_id: str | None = None) -> None:
    """Time and product checks on already signature-verified claims."""
    now = time.time() if now is None else now
    if product_id and claims["product_id"] != product_id:
        raise LicenseError(
            "PRODUCT_MISMATCH",
            f"License is for product '{claims['product_id']}', not '{product_id}'.",
            claims,
        )
    if claims["issued_at"] > now + CLOCK_SKEW_SECONDS:
        raise LicenseError("NOT_YET_VALID", "License issue time is in the future (check system clock).", claims)
    if claims["expires_at"] <= now:
        raise LicenseError("EXPIRED", "License has expired.", claims)


def verify_license_offline(
    token: str, public_key: Ed25519PublicKey, *, product_id: str | None = None, now: float | None = None
) -> dict[str, Any]:
    """Full offline check: format + signature + expiry + product. Revocation needs the server."""
    claims = decode_license_token(token, public_key)
    check_claims(claims, now=now, product_id=product_id)
    return claims


def verify_document(public_key: Ed25519PublicKey, signed: dict[str, Any]) -> dict[str, Any]:
    """Verify a document produced by `signing.sign_document` and return its payload."""
    try:
        payload = signed["payload"]
        signature = b64url_decode(signed["signature"])
    except Exception as exc:
        raise ValueError("Signed document is malformed") from exc
    if not verify_signature(public_key, canonical_json(payload), signature):
        raise ValueError("Signed document failed signature verification")
    return payload
