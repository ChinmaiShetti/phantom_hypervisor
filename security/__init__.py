"""PHANTOM shared security primitives (Ed25519 signing, verification, SHA-256 hashing).

This package is copied into BOTH containers. Only `signing.py` deals with the
private key, and only the server ever calls it with a real key.
"""
