"""SQLite persistence for license records, security events and client heartbeats.

All SQL lives in this one class (a small repository layer) and sticks to portable
SQL, so moving to PostgreSQL means re-implementing `_connect` with psycopg and
swapping `?` placeholders for `%s` - nothing else in the server touches SQL.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS licenses (
    license_id    TEXT PRIMARY KEY,
    product_id    TEXT NOT NULL,
    licensee      TEXT NOT NULL,
    issued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    revoked_at    INTEGER,
    revoke_reason TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    category  TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    severity  TEXT NOT NULL,
    source    TEXT NOT NULL,
    message   TEXT NOT NULL,
    details   TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    last_seen REAL NOT NULL,
    status    TEXT NOT NULL,
    details   TEXT
);
"""

MAX_EVENTS = 5000  # keep the database small; oldest events are pruned


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._tx() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock, closing(sqlite3.connect(self.path, timeout=10)) as conn:
            conn.row_factory = sqlite3.Row
            with conn:  # commit / rollback
                yield conn

    def ping(self) -> bool:
        try:
            with self._tx() as conn:
                conn.execute("SELECT 1")
            return True
        except sqlite3.Error:
            return False

    # ------------------------------------------------------------------ licenses
    def insert_license(self, rec: dict[str, Any]) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO licenses (license_id, product_id, licensee, issued_at, expires_at, status)"
                " VALUES (?, ?, ?, ?, ?, 'active')",
                (rec["license_id"], rec["product_id"], rec["licensee"], rec["issued_at"], rec["expires_at"]),
            )

    def get_license(self, license_id: str) -> dict[str, Any] | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
        return dict(row) if row else None

    def list_licenses(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute("SELECT * FROM licenses ORDER BY issued_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def revoke_license(self, license_id: str, reason: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE licenses SET status = 'revoked', revoked_at = ?, revoke_reason = ? WHERE license_id = ?",
                (int(time.time()), reason, license_id),
            )

    def license_counts(self, now: float) -> dict[str, int]:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total,"
                " SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked,"
                " SUM(CASE WHEN status != 'revoked' AND expires_at <= ? THEN 1 ELSE 0 END) AS expired,"
                " SUM(CASE WHEN status != 'revoked' AND expires_at > ? THEN 1 ELSE 0 END) AS active"
                " FROM licenses",
                (now, now),
            ).fetchone()
        return {k: int(row[k] or 0) for k in ("total", "active", "expired", "revoked")}

    # ------------------------------------------------------------------ events
    def add_event(self, category: str, outcome: str, severity: str, source: str, message: str,
                  details: dict[str, Any] | None = None) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO events (ts, category, outcome, severity, source, message, details)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), category, outcome, severity, source, message, json.dumps(details or {})),
            )
            event_id = cur.lastrowid
            if event_id % 200 == 0:  # cheap periodic pruning
                conn.execute("DELETE FROM events WHERE id <= ?", (event_id - MAX_EVENTS,))
        return int(event_id)

    def list_events(self, limit: int = 50, category: str | None = None,
                    severity: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM events WHERE 1=1", []
        if category:
            sql, args = sql + " AND category = ?", args + [category]
        if severity:
            sql, args = sql + " AND severity = ?", args + [severity]
        sql += " ORDER BY id DESC LIMIT ?"
        with self._tx() as conn:
            rows = conn.execute(sql, (*args, limit)).fetchall()
        return [{**dict(r), "details": json.loads(r["details"] or "{}")} for r in rows]

    def event_counts(self) -> dict[tuple[str, str], int]:
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT category, outcome, COUNT(*) AS n FROM events GROUP BY category, outcome"
            ).fetchall()
        return {(r["category"], r["outcome"]): int(r["n"]) for r in rows}

    def verification_codes(self) -> dict[str, int]:
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT details FROM events WHERE category = 'LICENSE_VERIFY' AND outcome = 'failure'"
            ).fetchall()
        counts: dict[str, int] = {}
        for r in rows:
            code = json.loads(r["details"] or "{}").get("code", "UNKNOWN")
            counts[code] = counts.get(code, 0) + 1
        return counts

    def events_since(self, since: float, categories: tuple[str, ...]) -> list[dict[str, Any]]:
        marks = ",".join("?" for _ in categories)
        with self._tx() as conn:
            rows = conn.execute(
                f"SELECT ts, category, outcome FROM events WHERE ts >= ? AND category IN ({marks})",
                (since, *categories),
            ).fetchall()
        return [dict(r) for r in rows]

    def last_event(self, category: str) -> dict[str, Any] | None:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE category = ? ORDER BY id DESC LIMIT 1", (category,)
            ).fetchone()
        return {**dict(row), "details": json.loads(row["details"] or "{}")} if row else None

    # ------------------------------------------------------------------ clients
    def upsert_client(self, client_id: str, status: str, details: dict[str, Any]) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO clients (client_id, last_seen, status, details) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(client_id) DO UPDATE SET last_seen = excluded.last_seen,"
                " status = excluded.status, details = excluded.details",
                (client_id, time.time(), status, json.dumps(details)),
            )

    def list_clients(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute("SELECT * FROM clients ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "details": json.loads(r["details"] or "{}")} for r in rows]
