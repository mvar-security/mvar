"""
Execution token nonce persistence store.

Append-only JSONL store for consumed execution-token nonces so one-time token
replay defense survives process restart.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict


class ExecutionTokenNonceStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._nonces: Dict[str, datetime] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                    nonce = str(item.get("nonce", ""))
                    expires_at = str(item.get("expires_at", ""))
                    if not nonce or not expires_at:
                        continue
                    dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) < dt:
                        self._nonces[nonce] = dt
                except Exception:
                    continue

    def _prune(self) -> None:
        now = datetime.now(timezone.utc)
        stale = [nonce for nonce, expiry in self._nonces.items() if now >= expiry]
        for nonce in stale:
            self._nonces.pop(nonce, None)

    def is_consumed(self, nonce: str) -> bool:
        self._prune()
        return nonce in self._nonces

    def consume(self, nonce: str, expires_at: datetime) -> None:
        self._prune()
        self._nonces[nonce] = expires_at
        entry = {
            "nonce": nonce,
            "expires_at": expires_at.isoformat(),
            "consumed_at": datetime.now(timezone.utc).isoformat(),
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
