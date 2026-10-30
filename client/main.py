"""PHANTOM protected client - a simulated DRM-protected application.

Commands (inside the container: `python -m client.main <command>`):
    run                 protection loop: re-checks every CHECK_INTERVAL_SECONDS (default)
    check               single check; exit code 0 = unlocked, 1 = locked
    activate <KEY>      install a license key
    status              show local license / configuration
    tamper | delete | restore   modify the local protected app (integrity demo)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from client.integrity import check_integrity, detect_environment, ensure_app_copy, load_trusted_manifest
from client.license_client import LicenseServerClient, ServerUnavailable
from monitoring.logger import setup_logging
from security.verification import LicenseError, load_public_key, peek_claims, verify_license_offline

REPO_ROOT = Path(__file__).resolve().parent.parent
log = setup_logging("phantom.client", json_format=False)


@dataclass
class Config:
    server_url: str = os.environ.get("LICENSE_SERVER_URL") or "http://phantom-server:8000"
    client_id: str = os.environ.get("CLIENT_ID") or f"client-{socket.gethostname()[:12]}"
    data_dir: Path = Path(os.environ.get("CLIENT_DATA_DIR") or REPO_ROOT / "data" / "client")
    public_key_b64: str = os.environ.get("PHANTOM_PUBLIC_KEY", "")
    license_env: str = os.environ.get("PHANTOM_LICENSE_KEY", "")
    product_id: str = os.environ.get("PHANTOM_PRODUCT_ID") or "PHANTOM-DEMO"
    interval: int = int(os.environ.get("CHECK_INTERVAL_SECONDS", "30"))
    grace: int = int(os.environ.get("OFFLINE_GRACE_SECONDS", "120"))
    debugger_policy: str = os.environ.get("DEBUGGER_POLICY", "warn")  # warn | block
    pristine_dir: Path = REPO_ROOT / "sample_app"

    @property
    def app_dir(self) -> Path:
        return self.data_dir / "app"

    def path(self, name: str) -> Path:
        return self.data_dir / name


@dataclass
class Decision:
    unlocked: bool
    mode: str  # online | offline-grace | locked
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------- helpers
def load_state(cfg: Config) -> dict[str, Any]:
    try:
        return json.loads(cfg.path("state.json").read_text())
    except (OSError, ValueError):
        return {}


def save_state(cfg: Config, state: dict[str, Any]) -> None:
    cfg.path("state.json").write_text(json.dumps(state))


def get_public_key(cfg: Config, server: LicenseServerClient):
    """Configured key > pinned key > fetch from server and pin (trust on first use)."""
    if cfg.public_key_b64:
        return load_public_key(cfg.public_key_b64)
    pinned = cfg.path("public_key.b64")
    if pinned.exists():
        return load_public_key(pinned.read_text())
    try:
        value = server.public_key()
    except ServerUnavailable:
        return None
    pinned.write_text(value)
    log.warning("No PHANTOM_PUBLIC_KEY configured - pinned server key on first use (TOFU).")
    return load_public_key(value)


def load_license(cfg: Config) -> str | None:
    if cfg.license_env:
        return cfg.license_env.strip()
    path = cfg.path("license.key")
    return path.read_text().strip() if path.exists() else None


# ---------------------------------------------------------------------------- protection check
def run_checks(cfg: Config, server: LicenseServerClient, state: dict[str, Any]) -> Decision:
    reasons: list[str] = []
    env = detect_environment()
    if env["debugger_detected"]:
        log.warning("[ENV ] Debugger/analysis indicators: %s (policy=%s)", ", ".join(env["indicators"]), cfg.debugger_policy)
        if cfg.debugger_policy == "block":
            reasons.append("debugger detected")

    public_key = get_public_key(cfg, server)
    if public_key is None:
        return Decision(False, "locked", ["no public key: license server unreachable and none pinned"])

    token = load_license(cfg)
    if not token:
        return Decision(False, "locked", ["no license installed - run: python -m client.main activate <KEY>"])

    # 1) Offline cryptographic checks (work with no network)
    offline_ok = False
    try:
        claims = verify_license_offline(token, public_key, product_id=cfg.product_id)
        offline_ok = True
        days = (claims["expires_at"] - time.time()) / 86400
        log.info("[ OK ] Offline license check: %s for '%s' (signature valid, %.1f days left)",
                 claims["license_id"], claims["licensee"], days)
    except LicenseError as err:
        reasons.append(f"license {err.code}: {err.message}")
        log.error("[FAIL] Offline license check: %s - %s", err.code, err.message)

    # 2) Integrity check against the server-signed manifest
    trusted, manifest_source = load_trusted_manifest(server, public_key, cfg.path("manifest.json"))
    integrity_status = "UNKNOWN"
    if trusted is None:
        reasons.append(f"no trusted integrity manifest ({manifest_source})")
    else:
        report = check_integrity(cfg.app_dir, trusted)
        integrity_status = report["status"]
        if report["status"] == "PASS":
            log.info("[ OK ] Integrity: %d files match signed manifest (%s)", report["summary"]["ok"], manifest_source)
        else:
            bad = [f"{f['path']}={f['status']}" for f in report["files"] if f["status"] != "OK"]
            reasons.append("integrity failure: " + ", ".join(bad))
            log.error("[FAIL] Integrity: TAMPERING DETECTED -> %s", ", ".join(bad))
        local = {f["path"]: f["actual"] for f in report["files"] if f["actual"]}

    # 3) Online verification (revocation, server-side logging)
    client_state = {"integrity": integrity_status, "environment": env, "local_ok": offline_ok and not reasons,
                    "local_reasons": reasons[:3], "manifest_source": manifest_source}
    try:
        if trusted is not None and integrity_status != state.get("last_integrity"):
            server.report_integrity(cfg.client_id, local)  # report only on change to keep logs readable
        status, body = server.verify(token, cfg.client_id, client_state, cfg.product_id)
        state["last_integrity"] = integrity_status
        if body.get("valid"):
            state["last_online_ok"] = time.time()
            log.info("[ OK ] Online verification: %s", body.get("message"))
        else:
            reasons.append(f"server rejected license: {body.get('code', status)} - {body.get('message', body)}")
            log.error("[FAIL] Online verification: %s - %s", body.get("code", status), body.get("message"))
        mode = "online"
    except ServerUnavailable as err:
        since = time.time() - state.get("last_online_ok", 0)
        remaining = cfg.grace - since
        log.warning("[WARN] License server unreachable (%s)", err)
        if remaining > 0:
            mode = "offline-grace"
            log.warning("[WARN] Offline grace period: %ds remaining before lock-out", remaining)
        else:
            mode = "locked"
            reasons.append("license server unreachable and offline grace period expired")

    unlocked = offline_ok and not reasons
    return Decision(unlocked, mode if unlocked else "locked", reasons,
                    {"integrity": integrity_status, "environment": env})


def print_decision(cfg: Config, d: Decision) -> None:
    if d.unlocked:
        payload = cfg.app_dir / "protected_sample.txt"
        unlocked_line = next((l for l in payload.read_text().splitlines() if l.startswith("UNLOCKED")), "")
        log.info("=== APPLICATION RUNNING [%s] === %s", d.mode.upper(), unlocked_line)
    else:
        log.error("=== APPLICATION LOCKED === %s", " | ".join(d.reasons))


# ---------------------------------------------------------------------------- commands
def cmd_run(cfg: Config, server: LicenseServerClient, once: bool) -> int:
    log.info("PHANTOM protected client '%s' -> license server %s", cfg.client_id, cfg.server_url)
    env = detect_environment()
    log.info("Environment: os=%s kernel=%s container=%s hypervisor_flag=%s",
             env["os"], env["kernel"], env["container"], env["hypervisor_flag"])
    while True:
        state = load_state(cfg)
        try:
            decision = run_checks(cfg, server, state)
        except Exception as exc:  # keep the protection loop alive
            log.exception("Protection check crashed: %s", exc)
            decision = Decision(False, "locked", [f"internal error: {exc}"])
        save_state(cfg, state)
        print_decision(cfg, decision)
        if once:
            return 0 if decision.unlocked else 1
        time.sleep(cfg.interval)


def cmd_activate(cfg: Config, key: str) -> int:
    claims = peek_claims(key)
    if not claims or not key.startswith("PHM1."):
        log.error("That does not look like a PHANTOM license key (expected PHM1.<payload>.<signature>).")
        return 2
    cfg.path("license.key").write_text(key.strip())
    log.info("License %s for '%s' installed. Signature is checked on the next run.",
             claims.get("license_id"), claims.get("licensee"))
    return 0


def cmd_status(cfg: Config) -> int:
    token = load_license(cfg)
    print(json.dumps({
        "client_id": cfg.client_id,
        "server_url": cfg.server_url,
        "license_installed": bool(token),
        "license_claims_unverified": peek_claims(token) if token else None,
        "public_key_source": "env" if cfg.public_key_b64 else ("pinned" if cfg.path("public_key.b64").exists() else "none"),
        "state": load_state(cfg),
    }, indent=2))
    return 0


def cmd_modify(cfg: Config, action: str) -> int:
    target = cfg.app_dir / "protected_sample.txt"
    if action == "tamper":
        with open(target, "a") as fh:
            fh.write("\n# PATCHED: if (!license_valid) -> NOP (simulated crack)\n")
        log.warning("Modified %s (simulated crack). Next check should detect it.", target)
    elif action == "delete":
        target.unlink(missing_ok=True)
        log.warning("Deleted %s. Next check should report it MISSING.", target)
    else:
        ensure_app_copy(cfg.pristine_dir, cfg.app_dir, force=True)
        log.info("Protected application restored from the original build.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phantom-client", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run")
    sub.add_parser("check")
    act = sub.add_parser("activate")
    act.add_argument("key")
    sub.add_parser("status")
    for name in ("tamper", "delete", "restore"):
        sub.add_parser(name)
    args = parser.parse_args(argv)

    cfg = Config()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    ensure_app_copy(cfg.pristine_dir, cfg.app_dir)
    server = LicenseServerClient(cfg.server_url)

    command = args.command or "run"
    if command in ("run", "check"):
        return cmd_run(cfg, server, once=command == "check")
    if command == "activate":
        return cmd_activate(cfg, args.key)
    if command == "status":
        return cmd_status(cfg)
    return cmd_modify(cfg, command)


if __name__ == "__main__":
    sys.exit(main())
