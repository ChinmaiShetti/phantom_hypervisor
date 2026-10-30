"""Minimal HTTP client for the PHANTOM license server (standard library only)."""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any


class ServerUnavailable(Exception):
    """Network failure, timeout, or 5xx: the license server could not answer."""


class LicenseServerClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json", "User-Agent": "phantom-client/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as err:
            if err.code >= 500:
                raise ServerUnavailable(f"server error HTTP {err.code}") from err
            try:
                payload = json.loads(err.read() or b"{}")
            except ValueError:
                payload = {"message": err.reason}
            return err.code, payload
        except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError) as err:
            raise ServerUnavailable(str(getattr(err, "reason", err))) from err

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")[1]

    def public_key(self) -> str:
        return self._request("GET", "/api/public-key")[1]["public_key"]

    def manifest(self) -> dict[str, Any]:
        return self._request("GET", "/api/integrity/manifest")[1]

    def verify(self, license_key: str, client_id: str, state: dict[str, Any], product_id: str | None = None) -> tuple[int, dict[str, Any]]:
        body = {"license_key": license_key, "client_id": client_id, "client_state": state}
        if product_id:
            body["product_id"] = product_id
        return self._request("POST", "/api/licenses/verify", body)

    def report_integrity(self, client_id: str, files: dict[str, str]) -> dict[str, Any]:
        return self._request("POST", "/api/integrity/verify", {"client_id": client_id, "files": files})[1]
