"""Append-only JSON-lines audit log.

Each line: {"ts", "op", "status", "blob_ids", "label_hashes", "label_count", "result_count", ...}.
The logger is strict by construction: operations come from an allow-list, blob IDs
must look like opaque identifiers, labels are hashed, and extra fields must be numbers
or booleans. There is no way to pass free text, so plaintext, keywords and secrets
cannot end up in audit.log by accident.
"""
from __future__ import annotations

import json
import os
import re
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from crypto_engine import fingerprint

OPERATIONS = frozenset({
    "upload", "search", "decrypt", "verify", "server_view", "setup",
    "drive_connect", "drive_disconnect", "key_created",
})
STATUSES = frozenset({"ok", "fail", "error"})
MAX_LABEL_HASHES = 256
# Opaque IDs only: random doc IDs (32 hex) or Drive file IDs. Short words are rejected.
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class AuditLogger:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._lock = threading.Lock()

    def log(
        self,
        op: str,
        *,
        status: str = "ok",
        blob_ids: Iterable[str] = (),
        labels: Iterable[bytes] = (),
        result_count: int | None = None,
        **extra: int | bool | None,
    ) -> dict:
        if op not in OPERATIONS:
            raise ValueError("unknown audit operation")
        if status not in STATUSES:
            raise ValueError("unknown audit status")
        ids = sorted(set(blob_ids))
        if not all(_ID_RE.fullmatch(i) for i in ids):
            raise ValueError("audit blob IDs must be opaque identifiers")
        for key, value in extra.items():
            if not re.fullmatch(r"[a-z_]{1,32}", key) or not isinstance(value, (int, bool, type(None))):
                raise ValueError("audit extras must be numeric or boolean")
        hashes = [fingerprint(label) for label in labels]
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "op": op,
            "status": status,
            "blob_ids": ids,
            "label_hashes": hashes[:MAX_LABEL_HASHES],
            "label_count": len(hashes),
            "result_count": result_count,
            **extra,
        }
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
        return entry

    def tail(self, limit: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        with self._lock, open(self.path, encoding="utf-8") as fh:
            lines = deque(fh, maxlen=limit)
        entries = []
        for line in reversed(lines):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"op": "corrupt_line", "status": "error"})
        return entries
