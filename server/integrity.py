"""Server-side integrity engine.

- The pristine sample application baked into the image is the source of truth.
- Its SHA-256 manifest is signed with the server key so clients can trust the
  reference hashes even when they later run offline.
- A disposable *workspace* copy lives in the data volume so the dashboard can
  demonstrate tampering without ever touching the pristine files.
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.hashing import compare_hashes, hash_directory, reset_tree
from security.signing import sign_document

TAMPER_MARKER = b"\n# PATCHED BY ATTACKER: license check bypassed (simulation)\n"
INJECTED_NAME = "injected_hook.dll.txt"


class IntegrityService:
    def __init__(self, pristine_dir: Path, workspace_dir: Path, private_key: Ed25519PrivateKey, product_id: str):
        self.pristine_dir = Path(pristine_dir)
        self.workspace_dir = Path(workspace_dir)
        self.trusted = hash_directory(self.pristine_dir)
        if not self.trusted:
            raise RuntimeError(f"No files found in sample application directory {self.pristine_dir}")
        self.manifest = {
            "product_id": product_id,
            "algorithm": "SHA-256",
            "generated_at": int(time.time()),
            "files": self.trusted,
        }
        self.signed_manifest = sign_document(private_key, self.manifest)
        self.restore()  # every server start begins with a clean demo workspace

    def verify_reported(self, reported: dict[str, str]) -> dict[str, Any]:
        """Compare hashes reported by a remote client with the trusted manifest."""
        return compare_hashes(self.trusted, reported)

    def verify_workspace(self) -> dict[str, Any]:
        return compare_hashes(self.trusted, hash_directory(self.workspace_dir))

    # ------------------------------------------------------------------ demo actions
    def _target(self, filename: str | None) -> Path:
        name = filename or next(iter(self.trusted))
        if name not in self.trusted:  # also blocks path traversal: only manifest names allowed
            raise ValueError(f"Unknown file '{name}'. Allowed: {', '.join(self.trusted)}")
        return self.workspace_dir / name

    def tamper(self, filename: str | None = None) -> str:
        target = self._target(filename)
        if not target.exists():
            shutil.copyfile(self.pristine_dir / target.relative_to(self.workspace_dir), target)
        with open(target, "ab") as fh:
            fh.write(TAMPER_MARKER)
        return f"Appended an unauthorised patch to {target.name}"

    def delete(self, filename: str | None = None) -> str:
        target = self._target(filename)
        target.unlink(missing_ok=True)
        return f"Deleted {target.name} from the protected application"

    def inject(self) -> str:
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace_dir / INJECTED_NAME).write_text("simulated injected module\n")
        return f"Dropped unexpected file {INJECTED_NAME} into the application directory"

    def restore(self) -> str:
        reset_tree(self.pristine_dir, self.workspace_dir)
        return "Restored the protected application from the trusted build"
