"""Logging setup shared by the PHANTOM server and client.

- Server: JSON lines on stdout (what `docker compose logs` and Render show) plus a
  small rotating file in the data volume (max ~3 MB on disk).
- Client: human-readable lines, because they are read live during the demo.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "event", None)
        if extra:
            entry["event"] = extra
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging(
    name: str, *, json_format: bool = True, log_file: Path | None = None, level: str = "INFO"
) -> logging.Logger:
    root = logging.getLogger()
    root.setLevel(level.upper())
    formatter: logging.Formatter = (
        JsonFormatter() if json_format else logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S")
    )
    # Idempotent: replace our handlers instead of stacking duplicates on reload.
    for handler in list(root.handlers):
        if getattr(handler, "_phantom", False):
            root.removeHandler(handler)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    stream._phantom = True  # type: ignore[attr-defined]
    root.addHandler(stream)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        rotating = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=2, encoding="utf-8")
        rotating.setFormatter(JsonFormatter())
        rotating._phantom = True  # type: ignore[attr-defined]
        root.addHandler(rotating)

    return logging.getLogger(name)
