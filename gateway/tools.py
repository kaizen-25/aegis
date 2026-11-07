"""Tool handlers.

Nothing outside `Gateway.execute()` (gateway/core.py) may call a handler. The handlers are only
reachable through the HANDLERS registry, and a test walks the AST of the whole package to prove
that the registry is dispatched from exactly one call site.

Every handler receives already validated and normalized arguments.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from contracts.enums import ToolName
from gateway.errors import ToolError

MAX_READ_BYTES = 200_000
MAX_ROWS = 200


@dataclass
class Draft:
    draft_id: str
    session_id: str
    to: str
    subject: str
    body: str
    sent: bool = False


@dataclass
class ToolEnv:
    """Everything a handler may touch."""

    sandbox: Path
    session_id: str
    mode: str
    now: datetime
    drafts: dict[str, Draft] = field(default_factory=dict)

    @property
    def files_root(self) -> Path:
        return self.sandbox / "files"

    @property
    def db_path(self) -> Path:
        return self.sandbox / "novacorp.db"


def list_tables(sandbox: Path) -> set[str]:
    """Table names that exist in the sandbox database: the allowlist for db.query and db.delete."""
    db = Path(sandbox) / "novacorp.db"
    if not db.exists():
        return set()
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        return {r[0].lower() for r in rows}
    finally:
        conn.close()


def _safe_file(env: ToolEnv, rel: str) -> Path:
    """Resolve a normalized relative path and prove it stays inside sandbox/files."""
    root = env.files_root.resolve()
    target = (root / rel).resolve()
    if root != target and root not in target.parents:
        raise ToolError("path is outside the sandbox")
    return target


def handle_file_read(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    target = _safe_file(env, args["path"])
    if not target.is_file():
        raise ToolError("file not found")
    data = target.read_bytes()[:MAX_READ_BYTES]
    return {"path": args["path"], "content": data.decode("utf-8", errors="replace")}


def handle_report_write(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    target = _safe_file(env, f"reports/{args['name']}.md")
    if target.parent.resolve() != (env.files_root / "reports").resolve():
        raise ToolError("reports must be saved directly under reports/")
    existed = target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(args["content"], encoding="utf-8", newline="\n")
    return {"path": f"reports/{args['name']}.md", "bytes": len(args["content"].encode("utf-8")),
            "overwritten": existed}


def _columns(conn: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    # `table` was matched against sqlite_master names before it got here; quote it anyway.
    return conn.execute(f'PRAGMA table_info("{table}")').fetchall()


# Comparison expressions that match the normalization applied to filter values.
_COLUMN_EXPR = {
    "email": 'lower("email")',
    "customer_id": 'upper("customer_id")',
    "account": 'upper("account")',
    "phone": "replace(replace(replace(replace(replace(\"phone\", ' ', ''), '+', ''), '-', ''), '(', ''), ')', '')",
}


def handle_db_query(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    table = args["table"]
    if table not in list_tables(env.sandbox):
        raise ToolError("unknown table")
    conn = sqlite3.connect(f"file:{env.db_path.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = {c["name"].lower(): c["name"] for c in _columns(conn, table)}
        where, params = [], []
        for key, value in args["filter"].items():
            if key not in columns:
                raise ToolError(f"unknown column {key!r}")
            real = columns[key]
            if key == "phone" and isinstance(value, str):
                where.append(_COLUMN_EXPR["phone"] + " = ?")
                params.append("".join(ch for ch in value if ch.isdigit()))
            elif key in _COLUMN_EXPR and isinstance(value, str):
                where.append(_COLUMN_EXPR[key] + " = ?")
                params.append(value)
            else:
                where.append(f'"{real}" = ?')
                params.append(value)
        sql = f'SELECT * FROM "{table}"' + (" WHERE " + " AND ".join(where) if where else "") + f" LIMIT {MAX_ROWS}"
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    except sqlite3.Error as exc:
        raise ToolError(f"database error: {exc.__class__.__name__}") from None
    finally:
        conn.close()
    return {"table": table, "count": len(rows), "rows": rows}


def handle_db_delete(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    table = args["table"]
    if table not in list_tables(env.sandbox):
        raise ToolError("unknown table")
    conn = sqlite3.connect(env.db_path)
    try:
        cols = _columns(conn, table)
        if not cols:
            raise ToolError("unknown table")
        key = next((c[1] for c in cols if c[5]), cols[0][1])
        cur = conn.execute(f'DELETE FROM "{table}" WHERE upper("{key}") = ?', (args["record_id"],))
        conn.commit()
        if cur.rowcount == 0:
            raise ToolError("no such record")
        return {"table": table, "deleted": cur.rowcount}
    except sqlite3.Error as exc:
        raise ToolError(f"database error: {exc.__class__.__name__}") from None
    finally:
        conn.close()


def handle_email_draft(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    draft_id = f"draft-{uuid.uuid4().hex[:12]}"
    env.drafts[draft_id] = Draft(draft_id, env.session_id, args["to"], args["subject"], args["body"])
    return {"draft_id": draft_id, "to": args["to"], "subject": args["subject"]}


def handle_email_send(env: ToolEnv, args: dict[str, Any]) -> dict[str, Any]:
    draft = env.drafts.get(args["draft_id"])
    if draft is None or draft.session_id != env.session_id:
        raise ToolError("no such draft in this session")
    if draft.sent:
        raise ToolError("draft was already sent")
    outbox = env.sandbox / "outbox" / env.mode
    outbox.mkdir(parents=True, exist_ok=True)
    email_id = f"mail-{uuid.uuid4().hex[:12]}"
    sent_at = env.now.isoformat()
    payload = {"email_id": email_id, "mode": env.mode, "session_id": env.session_id, "to": draft.to,
               "subject": draft.subject, "body": draft.body, "sent_at": sent_at}
    (outbox / f"{env.now.strftime('%Y%m%dT%H%M%S%f')}-{email_id}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    draft.sent = True
    return {"email_id": email_id, "to": draft.to, "subject": draft.subject, "outbox": env.mode}


Handler = Callable[[ToolEnv, dict[str, Any]], dict[str, Any]]

HANDLERS: dict[ToolName, Handler] = {
    ToolName.file_read: handle_file_read,
    ToolName.report_write: handle_report_write,
    ToolName.db_query: handle_db_query,
    ToolName.db_delete: handle_db_delete,
    ToolName.email_draft: handle_email_draft,
    ToolName.email_send: handle_email_send,
}
