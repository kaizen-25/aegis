"""Hash-chained audit log and the executions table, both in one SQLite file.

hash = sha256(prev_hash + canonical JSON of the row without `hash`). Writes are serialized
under a lock. Only masked values reach this module; raw values are never stored.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

JSON_COLUMNS = ("args_masked", "matched_rules", "flags", "result_masked")
COLUMNS = (
    "seq", "ts", "action_id", "session_id", "scenario_id", "step", "mode", "task", "tool",
    "args_masked", "matched_rules", "verdict", "status", "would_verdict", "explanation",
    "llm_explanation", "flags", "taint", "strikes", "result_masked", "error", "latency_ms",
    "prev_hash",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    action_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    mode TEXT NOT NULL,
    task TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_masked TEXT NOT NULL,
    matched_rules TEXT NOT NULL,
    verdict TEXT NOT NULL,
    status TEXT NOT NULL,
    would_verdict TEXT,
    explanation TEXT NOT NULL,
    llm_explanation TEXT NOT NULL,
    flags TEXT NOT NULL,
    taint TEXT NOT NULL,
    strikes INTEGER NOT NULL,
    result_masked TEXT,
    error TEXT,
    latency_ms REAL NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_session ON audit(session_id);
CREATE TABLE IF NOT EXISTS executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    record TEXT NOT NULL
);
"""


def canonical(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)


# Filled in after the row is written (by the background explainer), so it cannot be part of the hash.
UNHASHED = ("llm_explanation",)


def compute_hash(prev_hash: str, row_without_hash: dict[str, Any], legacy: bool = False) -> str:
    """sha256(prev_hash + canonical JSON of the row without `hash` and without `llm_explanation`)."""
    body = row_without_hash if legacy else {k: v for k, v in row_without_hash.items() if k not in UNHASHED}
    return hashlib.sha256((prev_hash + canonical(body)).encode("utf-8")).hexdigest()


def _decode(db_row: sqlite3.Row) -> dict[str, Any]:
    out = dict(db_row)
    for col in JSON_COLUMNS:
        if out.get(col) is not None:
            out[col] = json.loads(out[col])
    return out


class AuditStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """Append one record. `record` holds every AuditRecord field except seq, prev_hash and hash."""
        with self._lock:
            conn = self._connect()
            try:
                last = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
                seq = (last["seq"] + 1) if last else 1
                prev_hash = last["hash"] if last else GENESIS
                defaults = {"would_verdict": None, "llm_explanation": "", "result_masked": None, "error": None}
                row = {c: record.get(c, defaults.get(c)) for c in COLUMNS}
                row["seq"], row["prev_hash"] = seq, prev_hash
                row["latency_ms"] = float(row["latency_ms"])
                row["step"], row["strikes"] = int(row["step"]), int(row["strikes"])
                digest = compute_hash(prev_hash, row)
                values = [
                    json.dumps(row[c], sort_keys=True) if c in JSON_COLUMNS and row[c] is not None else row[c]
                    for c in COLUMNS
                ]
                conn.execute(
                    f"INSERT INTO audit ({', '.join(COLUMNS)}, hash) VALUES ({', '.join('?' * (len(COLUMNS) + 1))})",
                    [*values, digest],
                )
                conn.commit()
                return {**row, "hash": digest}
            finally:
                conn.close()

    def list(self, session_id: str | None = None, tool: str | None = None, verdict: str | None = None,
             rule: str | None = None, mode: str | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        for column, value in (("session_id", session_id), ("tool", tool), ("verdict", verdict), ("mode", mode)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        sql = "SELECT * FROM audit" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY seq"
        with self._lock:
            conn = self._connect()
            try:
                rows = [_decode(r) for r in conn.execute(sql, params).fetchall()]
            finally:
                conn.close()
        if rule:
            rows = [r for r in rows if rule in r["matched_rules"]]
        return rows

    def verify(self) -> tuple[bool, int | None]:
        """Recompute the whole chain. Returns (ok, first broken seq)."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM audit ORDER BY seq").fetchall()
            finally:
                conn.close()
        prev = GENESIS
        expected_seq = rows[0]["seq"] if rows else 1
        for db_row in rows:
            decoded = _decode(db_row)
            stored_hash = decoded.pop("hash")
            if decoded["seq"] != expected_seq or decoded["prev_hash"] != prev:
                return False, decoded["seq"]
            if compute_hash(prev, decoded) != stored_hash:
                # Rows written before llm_explanation was excluded were hashed with it (always "").
                if not (decoded["llm_explanation"] == "" and compute_hash(prev, decoded, legacy=True) == stored_hash):
                    return False, decoded["seq"]
            prev = stored_hash
            expected_seq += 1
        return True, None

    def set_llm_explanation(self, action_id: str, text: str) -> bool:
        """Late fill-in for the first row of an action. Not covered by the hash by design."""
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "UPDATE audit SET llm_explanation = ? WHERE seq = "
                    "(SELECT MIN(seq) FROM audit WHERE action_id = ?)", (text, action_id))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def record_execution(self, action_id: str, ts: str) -> None:
        """Called by gateway.execute() immediately before a handler runs."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("INSERT INTO executions (action_id, ts) VALUES (?, ?)", (action_id, ts))
                conn.commit()
            finally:
                conn.close()

    def executions(self) -> list[str]:
        with self._lock:
            conn = self._connect()
            try:
                return [r["action_id"] for r in conn.execute("SELECT action_id FROM executions ORDER BY id")]
            finally:
                conn.close()

    def save_session(self, session_id: str, record_json: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("INSERT OR REPLACE INTO sessions (session_id, record) VALUES (?, ?)",
                             (session_id, record_json))
                conn.commit()
            finally:
                conn.close()

    def clear_sessions(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM sessions")
                conn.commit()
            finally:
                conn.close()

    def clear_all(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM audit")
                conn.execute("DELETE FROM executions")
                conn.commit()
            finally:
                conn.close()
