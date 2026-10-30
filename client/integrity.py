"""Client-side anti-tamper checks: file integrity + simulated environment detection.

LIMITATIONS (deliberately documented - see README "Anti-tamper limitations"):
these checks run in the same process an attacker controls. A determined
attacker can patch them out, hook `sys.gettrace`, fake /proc, or edit this file
(which is why the files' hashes are also reported to the server). They raise the
cost of tampering; they cannot make it impossible.
"""
from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from client.license_client import LicenseServerClient, ServerUnavailable
from security.hashing import compare_hashes, hash_directory, reset_tree
from security.verification import verify_document


def ensure_app_copy(pristine_dir: Path, app_dir: Path, force: bool = False) -> None:
    """Install (or with force, reinstall) the protected application into the client's data volume."""
    if force or not app_dir.exists():
        reset_tree(pristine_dir, app_dir)


def load_trusted_manifest(server: LicenseServerClient, public_key: Ed25519PublicKey, cache: Path) -> tuple[dict[str, str] | None, str]:
    """Fetch the server-signed manifest (or fall back to the cached copy) and verify its signature."""
    signed, source = None, "server"
    try:
        signed = server.manifest()
    except ServerUnavailable:
        source = "cache"
    if signed is None and cache.exists():
        signed = json.loads(cache.read_text())
    if signed is None:
        return None, "unavailable"
    try:
        payload = verify_document(public_key, signed)
    except ValueError:
        return None, f"{source} (SIGNATURE INVALID)"
    if source == "server":
        cache.write_text(json.dumps(signed))
    return payload["files"], source


def check_integrity(app_dir: Path, trusted: dict[str, str]) -> dict[str, Any]:
    return compare_hashes(trusted, hash_directory(app_dir))


def _read(path: str) -> str:
    try:
        return Path(path).read_text(errors="ignore")
    except OSError:
        return ""


def detect_environment() -> dict[str, Any]:
    """Simulated debugger / analysis-environment detection (educational).

    Blocking indicators: Python trace hook (pdb, IDE debuggers), a ptrace tracer
    (gdb, strace) and the PHANTOM_SIMULATE_DEBUGGER switch used in the demo.
    Informational only: container and hypervisor hints - legitimate users run
    software in containers/VMs all the time, so we never block on these.
    """
    indicators: list[str] = []
    if sys.gettrace() is not None:
        indicators.append("python-trace-hook")
    status = _read("/proc/self/status")
    for line in status.splitlines():
        if line.startswith("TracerPid:") and line.split()[1] != "0":
            indicators.append(f"ptrace-tracer-pid-{line.split()[1]}")
    if os.environ.get("PHANTOM_SIMULATE_DEBUGGER", "").lower() in {"1", "true", "yes"}:
        indicators.append("simulated-debugger")

    cgroup = _read("/proc/1/cgroup")
    in_container = Path("/.dockerenv").exists() or "docker" in cgroup or "containerd" in cgroup
    cpu_flags = _read("/proc/cpuinfo")
    return {
        "debugger_detected": bool(indicators),
        "indicators": indicators,
        "container": in_container,
        "hypervisor_flag": " hypervisor" in cpu_flags,
        "kernel": platform.release(),
        "os": platform.system(),
        "python": platform.python_version(),
    }
