"""PHANTOM license server: FastAPI REST API + monitoring dashboard.

Run locally:   uvicorn server.main:app --reload
In Docker:     see server/Dockerfile (binds 0.0.0.0:$PORT, works on Render).
"""
from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from monitoring.logger import setup_logging
from server.config import PRODUCT_ID_PATTERN, Settings
from server.database import Database
from server.integrity import IntegrityService
from server.license_manager import LicenseManager
from server.validator import validate_license

VERSION = "1.0.0"
PRODUCT_RE = PRODUCT_ID_PATTERN.pattern
CLIENT_ID_RE = r"^[A-Za-z0-9_.:-]{1,64}$"
SEVERITY_LEVEL = {"info": logging.INFO, "warning": logging.WARNING, "critical": logging.ERROR}
ERROR_NAMES = {400: "BAD_REQUEST", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND",
               409: "CONFLICT", 422: "VALIDATION_ERROR", 429: "RATE_LIMITED", 500: "INTERNAL_ERROR"}


# ============================================================================ request models
class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    licensee: str = Field(..., min_length=1, max_length=64, description="Customer / user name")
    product_id: str | None = Field(None, pattern=PRODUCT_RE)
    valid_days: int = Field(30, ge=-365, le=3650, description="Validity in days. Negative = already expired (for testing).")


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    license_key: str = Field(..., min_length=1, max_length=4096)
    product_id: str | None = Field(None, pattern=PRODUCT_RE)
    client_id: str | None = Field(None, pattern=CLIENT_ID_RE)
    client_state: dict[str, Any] | None = Field(None, description="Optional client self-report (integrity, environment)")

    @field_validator("client_state")
    @classmethod
    def _small_state(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and len(json.dumps(v, default=str)) > 4096:
            raise ValueError("client_state is too large (max 4 KB)")
        return v


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    license_id: str = Field(..., min_length=1, max_length=64)
    reason: str = Field("Revoked by administrator", max_length=200)


class IntegrityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: str | None = Field(None, pattern=CLIENT_ID_RE)
    files: dict[str, str] | None = Field(None, description="path -> SHA-256 hex. Omit to check the server demo workspace.")

    @field_validator("files")
    @classmethod
    def _valid_hashes(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is None:
            return v
        if len(v) > 500:
            raise ValueError("Too many files (max 500)")
        for path, digest in v.items():
            if len(path) > 255:
                raise ValueError("File path too long")
            if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
                raise ValueError(f"'{path}' does not have a valid SHA-256 hex digest")
        return v


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["tamper", "delete", "inject", "restore"]
    file: str | None = Field(None, max_length=255)


# ============================================================================ rate limiting
class RateLimiter:
    """In-memory sliding-window limiter per client IP. Fine for a single instance;
    multi-instance deployments would need a shared store."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory
                self._hits = defaultdict(deque, {k: d for k, d in self._hits.items() if d})
            return True


# ============================================================================ application factory
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    log = setup_logging("phantom.server", json_format=True, log_file=settings.data_dir / "logs" / "server.log")

    private_key = settings.load_signing_key()
    admin_secret = settings.resolve_admin_secret()
    db = Database(settings.data_dir / "phantom.db")
    licenses = LicenseManager(db, private_key, settings.revoked_ids)
    integrity = IntegrityService(settings.sample_dir, settings.data_dir / "workspace", private_key, settings.product_id)
    del private_key  # only the two services above keep a reference
    started_at = time.time()
    public_limiter = RateLimiter(settings.rate_limit_per_minute)
    admin_limiter = RateLimiter(settings.admin_rate_limit_per_minute)

    def emit(category: str, outcome: str, severity: str, message: str, source: str = "server", **details: Any) -> None:
        db.add_event(category, outcome, severity, source, message, details)
        log.log(SEVERITY_LEVEL.get(severity, logging.INFO), message,
                extra={"event": {"category": category, "outcome": outcome, "source": source, **details}})

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        emit("SERVER", "start", "info", f"License server started ({settings.app_env}), key {licenses.fingerprint}")
        yield
        emit("SERVER", "stop", "info", "License server shutting down")

    app = FastAPI(
        title="PHANTOM License Server",
        version=VERSION,
        description="Educational DRM / anti-tamper simulation: Ed25519 licensing, SHA-256 integrity, monitoring.",
        lifespan=lifespan,
    )
    app.state.settings, app.state.db, app.state.licenses, app.state.integrity = settings, db, licenses, integrity

    # ------------------------------------------------------------------ error handling (uniform JSON)
    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": ERROR_NAMES.get(exc.status_code, "ERROR"), "message": exc.detail},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError):
        errors = [{"field": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"error": "VALIDATION_ERROR",
                                                      "message": "Request validation failed.", "details": errors})

    @app.exception_handler(Exception)
    async def unhandled_error(_: Request, exc: Exception):
        log.exception("Unhandled error: %s", exc)
        return JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR", "message": "Internal server error."})

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # ------------------------------------------------------------------ dependencies
    def client_ip(request: Request) -> str:
        # uvicorn --proxy-headers resolves X-Forwarded-For (Render's proxy) into request.client
        return request.client.host if request.client else "unknown"

    def rate_limited(request: Request) -> None:
        ip = client_ip(request)
        if not public_limiter.allow(ip):
            emit("SECURITY", "rate_limited", "warning", f"Rate limit exceeded on {request.url.path}", ip=ip)
            raise HTTPException(429, "Too many requests. Slow down.", headers={"Retry-After": "60"})

    def require_admin(request: Request, x_admin_secret: str | None = Header(None)) -> None:
        ip = client_ip(request)
        if not admin_limiter.allow(ip):
            emit("SECURITY", "rate_limited", "warning", f"Admin rate limit exceeded on {request.url.path}", ip=ip)
            raise HTTPException(429, "Too many administrative requests.", headers={"Retry-After": "60"})
        if not x_admin_secret:
            raise HTTPException(401, "Administrative endpoint: X-Admin-Secret header required.")
        if not hmac.compare_digest(x_admin_secret.encode(), admin_secret.encode()):
            emit("SECURITY", "auth_failure", "warning", f"Rejected admin request to {request.url.path}: bad secret", ip=ip)
            raise HTTPException(403, "Invalid admin secret.")

    # ------------------------------------------------------------------ public endpoints
    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/dashboard/")

    @app.get("/health", tags=["system"])
    def health():
        db_ok = db.ping()
        return JSONResponse(
            status_code=200 if db_ok else 503,
            content={
                "status": "ok" if db_ok else "degraded",
                "service": "phantom-license-server",
                "version": VERSION,
                "environment": settings.app_env,
                "uptime_seconds": round(time.time() - started_at, 1),
                "database": "ok" if db_ok else "error",
                "key_fingerprint": licenses.fingerprint,
                "server_time": time.time(),
            },
        )

    @app.get("/api/public-key", tags=["licenses"])
    def public_key():
        """Public verification key. Safe to publish; the private key never leaves the server."""
        return {"algorithm": "Ed25519", "public_key": licenses.public_key_b64, "fingerprint": licenses.fingerprint}

    @app.post("/api/licenses/generate", status_code=201, tags=["licenses"], dependencies=[Depends(require_admin)])
    def generate_license(body: GenerateRequest):
        token, record = licenses.issue(body.product_id or settings.product_id, body.licensee.strip(), body.valid_days)
        emit("LICENSE_ISSUE", "success", "info",
             f"Issued {record['license_id']} to '{record['licensee']}' ({body.valid_days} days)",
             source="admin", license_id=record["license_id"], valid_days=body.valid_days)
        return {"license_key": token, "license": record,
                "message": "License issued. Distribute the key to the client; keep the admin secret private."}

    @app.post("/api/licenses/verify", tags=["licenses"], dependencies=[Depends(rate_limited)])
    def verify_license(body: VerifyRequest, request: Request):
        result = validate_license(body.license_key, licenses, product_id=body.product_id,
                                  strict_registry=settings.strict_registry)
        source = body.client_id or "anonymous"
        claims = result.claims or {}
        lid = claims.get("license_id") or (claims.get("unverified_claims") or {}).get("license_id")
        emit("LICENSE_VERIFY", "success" if result.valid else "failure",
             "info" if result.valid else ("critical" if result.code == "BAD_SIGNATURE" else "warning"),
             f"{'VALID' if result.valid else 'REJECTED'} [{result.code}] {lid or 'unparseable license'}",
             source=source, code=result.code, license_id=lid, ip=client_ip(request))

        if body.client_id:
            state = body.client_state or {}
            running = result.valid and state.get("integrity", "PASS") == "PASS" and state.get("local_ok", True)
            db.upsert_client(body.client_id, "RUNNING" if running else "LOCKED",
                             {**state, "license_code": result.code, "license_id": lid})
            env = state.get("environment") or {}
            if env.get("debugger_detected"):
                emit("ENVIRONMENT", "debugger", "warning", f"Client {body.client_id} reports a debugger/tracer",
                     source=body.client_id, indicators=env.get("indicators", []))
        return JSONResponse(status_code=result.http_status, content=result.to_dict())

    @app.post("/api/licenses/revoke", tags=["licenses"], dependencies=[Depends(require_admin)])
    def revoke_license(body: RevokeRequest):
        existing = db.get_license(body.license_id)
        if existing is None:
            raise HTTPException(404, f"License {body.license_id} not found in registry.")
        if existing["status"] == "revoked":
            raise HTTPException(409, f"License {body.license_id} is already revoked.")
        record = licenses.revoke(body.license_id, body.reason)
        emit("LICENSE_REVOKE", "success", "warning", f"Revoked {body.license_id}: {body.reason}",
             source="admin", license_id=body.license_id)
        return {"revoked": True, "license": record}

    @app.get("/api/licenses", tags=["licenses"], dependencies=[Depends(require_admin)])
    def list_licenses(limit: int = Query(50, ge=1, le=500)):
        return {"licenses": licenses.list(limit)}

    @app.get("/api/integrity/manifest", tags=["integrity"])
    def integrity_manifest():
        """Signed SHA-256 reference manifest. Clients verify it with the public key."""
        return integrity.signed_manifest

    @app.post("/api/integrity/verify", tags=["integrity"], dependencies=[Depends(rate_limited)])
    def verify_integrity(body: IntegrityRequest | None = None):
        body = body or IntegrityRequest()
        if body.files is not None:
            report, target = integrity.verify_reported(body.files), body.client_id or "remote-client"
        else:
            report, target = integrity.verify_workspace(), "server-workspace"
        bad = [f"{f['path']}:{f['status']}" for f in report["files"] if f["status"] != "OK"]
        if report["status"] == "PASS":
            emit("INTEGRITY", "pass", "info", f"Integrity verified for {target} ({report['summary']['ok']} files)",
                 source=target)
        else:
            emit("INTEGRITY", "fail", "critical", f"TAMPERING DETECTED on {target}: {', '.join(bad)}",
                 source=target, findings=bad)
        return {"target": target, **report}

    @app.post("/api/integrity/simulate", tags=["integrity"], dependencies=[Depends(require_admin)])
    def simulate_tamper(body: SimulateRequest):
        """Demo only: modify the server's disposable workspace copy of the sample app."""
        try:
            if body.action == "tamper":
                message = integrity.tamper(body.file)
            elif body.action == "delete":
                message = integrity.delete(body.file)
            elif body.action == "inject":
                message = integrity.inject()
            else:
                message = integrity.restore()
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        emit("DEMO", body.action, "info", f"Simulation: {message}", source="admin")
        return {"action": body.action, "message": message}

    @app.get("/api/events", tags=["monitoring"])
    def events(limit: int = Query(50, ge=1, le=500),
               category: str | None = Query(None, max_length=32),
               severity: Literal["info", "warning", "critical"] | None = None):
        return {"events": db.list_events(limit, category, severity)}

    @app.get("/api/stats", tags=["monitoring"])
    def stats():
        now = time.time()
        counts = db.event_counts()
        c = lambda cat, out: counts.get((cat, out), 0)  # noqa: E731
        by_code = db.verification_codes()
        last_integrity = db.last_event("INTEGRITY")

        # Per-minute verification timeline for the last 30 minutes
        buckets = {int(now // 60) - i: {"valid": 0, "failed": 0, "tamper": 0} for i in range(29, -1, -1)}
        for e in db.events_since(now - 30 * 60, ("LICENSE_VERIFY", "INTEGRITY")):
            b = buckets.get(int(e["ts"] // 60))
            if b is None:
                continue
            if e["category"] == "LICENSE_VERIFY":
                b["valid" if e["outcome"] == "success" else "failed"] += 1
            elif e["outcome"] == "fail":
                b["tamper"] += 1

        clients = db.list_clients()
        for cl in clients:
            cl["online"] = now - cl["last_seen"] < 90
        return {
            "server": {"status": "online", "environment": settings.app_env, "version": VERSION,
                       "uptime_seconds": round(now - started_at, 1), "key_fingerprint": licenses.fingerprint,
                       "product_id": settings.product_id, "strict_registry": settings.strict_registry},
            "licenses": db.license_counts(now),
            "verifications": {
                "total": c("LICENSE_VERIFY", "success") + c("LICENSE_VERIFY", "failure"),
                "valid": c("LICENSE_VERIFY", "success"),
                "failed": c("LICENSE_VERIFY", "failure"),
                "by_code": by_code,
            },
            "integrity": {
                "checks": c("INTEGRITY", "pass") + c("INTEGRITY", "fail"),
                "failures": c("INTEGRITY", "fail"),
                "last_status": None if not last_integrity else ("PASS" if last_integrity["outcome"] == "pass" else "FAIL"),
                "last_target": last_integrity["source"] if last_integrity else None,
                "last_checked_at": last_integrity["ts"] if last_integrity else None,
                "workspace": integrity.verify_workspace()["status"],
                "trusted_files": len(integrity.trusted),
            },
            "security": {"auth_failures": c("SECURITY", "auth_failure"), "rate_limited": c("SECURITY", "rate_limited"),
                         "environment_alerts": c("ENVIRONMENT", "debugger")},
            "clients": clients,
            "timeline": [{"minute": m * 60, **v} for m, v in buckets.items()],
        }

    if settings.dashboard_dir.is_dir():
        app.mount("/dashboard", StaticFiles(directory=settings.dashboard_dir, html=True), name="dashboard")

    return app


app = create_app()
