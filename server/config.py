"""Server configuration, read from environment variables (12-factor style).

Development: missing secrets are generated once and persisted in DATA_DIR so the
stack works straight after `docker compose up`.
Production (APP_ENV=production, e.g. Render): secrets MUST come from the
environment, otherwise the server refuses to start.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.signing import generate_private_key, load_private_key, private_key_to_b64

log = logging.getLogger("phantom.config")

PRODUCT_ID_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,31}$")
REPO_ROOT = Path(__file__).resolve().parent.parent


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    app_env: str = "development"
    data_dir: Path = REPO_ROOT / "data"
    private_key_b64: str = ""
    admin_secret: str = ""
    product_id: str = "PHANTOM-DEMO"
    revoked_ids: set[str] = field(default_factory=set)
    strict_registry: bool = False
    rate_limit_per_minute: int = 120
    admin_rate_limit_per_minute: int = 30
    sample_dir: Path = REPO_ROOT / "sample_app"
    dashboard_dir: Path = REPO_ROOT / "dashboard"

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        return cls(
            app_env=env.get("APP_ENV", "development"),
            data_dir=Path(env.get("DATA_DIR") or REPO_ROOT / "data"),
            private_key_b64=env.get("PHANTOM_PRIVATE_KEY", ""),
            admin_secret=env.get("PHANTOM_ADMIN_SECRET", ""),
            product_id=env.get("PHANTOM_PRODUCT_ID", "PHANTOM-DEMO") or "PHANTOM-DEMO",
            revoked_ids={x.strip() for x in env.get("PHANTOM_REVOKED_LICENSES", "").split(",") if x.strip()},
            strict_registry=_bool(env.get("PHANTOM_STRICT_REGISTRY")),
            rate_limit_per_minute=int(env.get("RATE_LIMIT_PER_MINUTE", "120")),
            admin_rate_limit_per_minute=int(env.get("ADMIN_RATE_LIMIT_PER_MINUTE", "30")),
        )

    # ------------------------------------------------------------------ secrets
    def load_signing_key(self) -> Ed25519PrivateKey:
        if self.private_key_b64:
            return load_private_key(self.private_key_b64)
        if self.is_production:
            raise RuntimeError("PHANTOM_PRIVATE_KEY must be set when APP_ENV=production")
        path = self.data_dir / "dev_signing_key.b64"
        if path.exists():
            return load_private_key(path.read_text())
        key = generate_private_key()
        _write_secret(path, private_key_to_b64(key))
        log.warning("No PHANTOM_PRIVATE_KEY set: generated a DEVELOPMENT signing key at %s", path)
        return key

    def resolve_admin_secret(self) -> str:
        if self.admin_secret:
            if self.is_production and len(self.admin_secret) < 16:
                raise RuntimeError("PHANTOM_ADMIN_SECRET must be at least 16 characters in production")
            return self.admin_secret
        if self.is_production:
            raise RuntimeError("PHANTOM_ADMIN_SECRET must be set when APP_ENV=production")
        path = self.data_dir / "dev_admin_secret"
        if path.exists():
            return path.read_text().strip()
        value = secrets.token_urlsafe(18)
        _write_secret(path, value)
        log.warning("No PHANTOM_ADMIN_SECRET set: generated DEVELOPMENT admin secret: %s", value)
        return value

    def validate(self) -> None:
        if not PRODUCT_ID_PATTERN.match(self.product_id):
            raise RuntimeError(f"PHANTOM_PRODUCT_ID '{self.product_id}' is invalid (A-Z, 0-9, '-', 3-32 chars)")
        if self.rate_limit_per_minute < 1 or self.admin_rate_limit_per_minute < 1:
            raise RuntimeError("Rate limits must be positive integers")


def _write_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    try:
        path.chmod(0o600)  # owner read/write only (no-op semantics on Windows)
    except OSError:
        pass
