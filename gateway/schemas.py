"""Per-tool argument schemas (contracts-spec section 2.1) and argument normalization."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from contracts.enums import ToolName
from gateway.errors import FailClosed
from gateway.normalize import (
    normalize_email,
    normalize_id,
    normalize_path,
    normalize_report_name,
)

MAX_TEXT = 100_000
MAX_FILTER_KEYS = 8


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FileReadArgs(_Strict):
    path: str


class ReportWriteArgs(_Strict):
    name: str
    content: str


class DbQueryArgs(_Strict):
    table: str
    filter: dict[str, Any] = {}


class DbDeleteArgs(_Strict):
    table: str
    record_id: str


class EmailDraftArgs(_Strict):
    to: str
    subject: str
    body: str


class EmailSendArgs(_Strict):
    draft_id: str


SCHEMAS: dict[ToolName, type[BaseModel]] = {
    ToolName.file_read: FileReadArgs,
    ToolName.report_write: ReportWriteArgs,
    ToolName.db_query: DbQueryArgs,
    ToolName.db_delete: DbDeleteArgs,
    ToolName.email_draft: EmailDraftArgs,
    ToolName.email_send: EmailSendArgs,
}

# Columns whose values get an identifier-specific normalization in filters.
_UPPER_COLUMNS = {"customer_id", "account"}
_LOWER_COLUMNS = {"email"}


def validate_and_normalize(tool: ToolName, args: Any, known_tables: set[str]) -> dict[str, Any]:
    """Validate against the tool schema, then normalize. Raises FailClosed on any problem."""
    if not isinstance(args, dict):
        raise FailClosed("args must be an object")
    try:
        model = SCHEMAS[tool].model_validate(args)
    except ValidationError as exc:
        # Report field names only: pydantic's default text echoes the offending value.
        fields = sorted({".".join(str(p) for p in err["loc"]) or "args" for err in exc.errors()})
        raise FailClosed(f"invalid arguments for {tool.value}: {', '.join(fields)}") from None
    data = model.model_dump()

    if tool is ToolName.file_read:
        return {"path": normalize_path(data["path"])}

    if tool is ToolName.report_write:
        if len(data["content"]) > MAX_TEXT:
            raise FailClosed("report content is too large")
        return {"name": normalize_report_name(data["name"]), "content": data["content"]}

    if tool in (ToolName.db_query, ToolName.db_delete):
        table = data["table"].strip().lower()
        if table not in known_tables:
            raise FailClosed("unknown table")
        if tool is ToolName.db_delete:
            record_id = normalize_id(data["record_id"])
            if not record_id or len(record_id) > 100:
                raise FailClosed("invalid record id")
            return {"table": table, "record_id": record_id}
        flt = data["filter"]
        if len(flt) > MAX_FILTER_KEYS:
            raise FailClosed("too many filter keys")
        clean: dict[str, Any] = {}
        for key, value in flt.items():
            if not isinstance(key, str) or not key.strip():
                raise FailClosed("invalid filter key")
            if not isinstance(value, (str, int, float, bool)) and value is not None:
                raise FailClosed("filter values must be scalars")
            column = key.strip().lower()
            if isinstance(value, str):
                if column in _UPPER_COLUMNS:
                    value = normalize_id(value)
                elif column in _LOWER_COLUMNS:
                    value = value.strip().lower()
            clean[column] = value
        return {"table": table, "filter": clean}

    if tool is ToolName.email_draft:
        if len(data["body"]) > MAX_TEXT or len(data["subject"]) > 1000:
            raise FailClosed("draft is too large")
        return {"to": normalize_email(data["to"]), "subject": data["subject"], "body": data["body"]}

    if tool is ToolName.email_send:
        draft_id = data["draft_id"].strip()
        if not draft_id or len(draft_id) > 100:
            raise FailClosed("invalid draft id")
        return {"draft_id": draft_id}

    raise FailClosed("unknown tool")  # pragma: no cover
