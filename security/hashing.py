"""SHA-256 file hashing and manifest comparison, shared by client and server."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import time
from pathlib import Path

CHUNK = 64 * 1024


def reset_tree(src: Path, dst: Path) -> None:
    """Replace dst with a fresh, owner-writable copy of src.

    The images make /app read-only, and copytree would carry those permission
    bits into the data volume, so permissions are reset after copying.
    """
    def make_writable(root: Path) -> None:
        for path in [root, *root.rglob("*")]:
            os.chmod(path, path.stat().st_mode | stat.S_IWUSR)

    if dst.exists():
        make_writable(dst)
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    make_writable(dst)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_directory(root: Path) -> dict[str, str]:
    """Map of POSIX-style relative path -> SHA-256 for every regular file under root."""
    root = Path(root)
    if not root.is_dir():
        return {}
    return {
        p.relative_to(root).as_posix(): sha256_file(p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def compare_hashes(trusted: dict[str, str], actual: dict[str, str]) -> dict:
    """Compare trusted reference hashes with observed hashes and build a report.

    Statuses: OK, MODIFIED, MISSING (trusted file absent), UNEXPECTED (extra file,
    e.g. an injected payload). Anything other than OK fails the check.
    """
    files = []
    for path in sorted(set(trusted) | set(actual)):
        expected, observed = trusted.get(path), actual.get(path)
        if expected is None:
            status = "UNEXPECTED"
        elif observed is None:
            status = "MISSING"
        elif observed.lower() == expected.lower():
            status = "OK"
        else:
            status = "MODIFIED"
        files.append({"path": path, "status": status, "expected": expected, "actual": observed})

    summary = {s.lower(): sum(f["status"] == s for f in files) for s in ("OK", "MODIFIED", "MISSING", "UNEXPECTED")}
    passed = bool(files) and summary["ok"] == len(files)
    return {
        "status": "PASS" if passed else "FAIL",
        "algorithm": "SHA-256",
        "checked_at": time.time(),
        "summary": summary,
        "files": files,
    }
