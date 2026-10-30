"""Ed25519 key management and signing (license-server side).

License token format (similar in spirit to a compact JWS):

    PHM1.<base64url(canonical JSON claims)>.<base64url(Ed25519 signature)>

The signature covers the ASCII bytes of "PHM1.<payload>", so neither the
version prefix nor any claim can be altered without invalidating it.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOKEN_PREFIX = "PHM1"


# --------------------------------------------------------------------------- encoding helpers
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON so the same claims always produce the same bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


# --------------------------------------------------------------------------- keys
def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_b64(key: Ed25519PrivateKey) -> str:
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def load_private_key(b64_value: str) -> Ed25519PrivateKey:
    try:
        raw = base64.b64decode(b64_value.strip(), validate=True)
    except Exception as exc:  # binascii.Error, ValueError
        raise ValueError("PHANTOM_PRIVATE_KEY is not valid base64") from exc
    if len(raw) != 32:
        raise ValueError("PHANTOM_PRIVATE_KEY must decode to a 32-byte Ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def key_fingerprint(public_b64: str) -> str:
    """Short, human-comparable fingerprint of a public key (first 64 bits of SHA-256)."""
    digest = hashlib.sha256(base64.b64decode(public_b64)).hexdigest()[:16]
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))


# --------------------------------------------------------------------------- signing
def issue_license_token(key: Ed25519PrivateKey, claims: dict[str, Any]) -> str:
    signing_input = f"{TOKEN_PREFIX}.{b64url_encode(canonical_json(claims))}"
    signature = key.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{b64url_encode(signature)}"


def sign_document(key: Ed25519PrivateKey, document: dict[str, Any]) -> dict[str, Any]:
    """Wrap an arbitrary JSON document (e.g. the integrity manifest) with a signature."""
    return {
        "payload": document,
        "signature": b64url_encode(key.sign(canonical_json(document))),
        "algorithm": "Ed25519",
        "key_id": key_fingerprint(public_key_b64(key)),
    }
