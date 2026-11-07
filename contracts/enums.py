"""Shared enums, exactly as listed in docs/contracts-spec.md section 1. FROZEN."""
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class ExecStatus(str, Enum):
    EXECUTED = "EXECUTED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    BLOCKED = "BLOCKED"
    FAIL_CLOSED = "FAIL_CLOSED"
    PENDING = "PENDING"
    PARKED = "PARKED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class Classification(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class Risk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Urgency(str, Enum):
    low = "low"
    normal = "normal"
    high = "high"


class RuleKind(str, Enum):
    tool_access = "tool_access"
    resource_access = "resource_access"
    prohibited = "prohibited"
    requires_approval = "requires_approval"
    flow = "flow"
    escalation = "escalation"


class ToolName(str, Enum):
    file_read = "file.read"
    report_write = "report.write"
    db_query = "db.query"
    db_delete = "db.delete"
    email_draft = "email.draft"
    email_send = "email.send"


class GatewayMode(str, Enum):
    protected = "protected"
    passthrough = "passthrough"


class AgentKind(str, Enum):
    scripted = "scripted"
    llm = "llm"


class SessionState(str, Enum):
    active = "active"
    on_watch = "on_watch"
    frozen = "frozen"
    suspended = "suspended"
    completed = "completed"


class Flag(str, Enum):
    OFF_TASK = "OFF_TASK"
    UNTRUSTED_CONTENT = "UNTRUSTED_CONTENT"
    URGENCY_CLAIM = "URGENCY_CLAIM"
    LLM_CONCERN = "LLM_CONCERN"
    CONTENT_MATCH = "CONTENT_MATCH"
    SYSTEM_FAIL_CLOSED = "SYSTEM_FAIL_CLOSED"


class TicketState(str, Enum):
    pending = "pending"
    parked = "parked"
    approved = "approved"
    rejected = "rejected"


class LiveEventType(str, Enum):
    decision = "decision"
    ticket = "ticket"
    ticket_update = "ticket_update"
    session_update = "session_update"
    explanation_ready = "explanation_ready"
    eval_progress = "eval_progress"


class ScenarioCategory(str, Enum):
    injection = "injection"
    exfiltration = "exfiltration"
    destructive = "destructive"
    circumvention = "circumvention"
    benign = "benign"
    ambiguous = "ambiguous"
    timeout = "timeout"
    known_miss = "known_miss"
