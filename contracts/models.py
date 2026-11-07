"""Shared data shapes from docs/contracts-spec.md sections 2 and 4. FROZEN.

Differences from the spec, all agreed before the freeze:
- The section 2.5 model is called SessionRecord, because the section 1 enum is
  already called SessionState. Its field names are unchanged.
- The policy format gains optional fields (marked below), because the spec's
  `match` and `when` keys could not express every rule in the Rulebook.
- The scenario reviewer also accepts `late_approve`, which T1 needs.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from contracts.enums import (
    AgentKind,
    Classification,
    ExecStatus,
    Flag,
    GatewayMode,
    LiveEventType,
    Risk,
    RuleKind,
    ScenarioCategory,
    SessionState,
    TicketState,
    ToolName,
    Urgency,
    Verdict,
)


class TaskScope(BaseModel):
    """Section 4.2."""

    model_config = ConfigDict(extra="forbid")

    task: str
    allowed_tools: list[ToolName]
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_recipients: list[str] = Field(default_factory=list)
    urgency: Urgency = Urgency.normal


class ActionRequest(BaseModel):
    """Section 2.1, agent to gateway."""

    session_id: str
    step: int
    tool: ToolName
    args: dict[str, Any]
    agent_kind: AgentKind
    agent_note: str | None = None


class Decision(BaseModel):
    """Section 2.2, gateway to agent."""

    action_id: str
    verdict: Verdict
    status: ExecStatus
    matched_rules: list[str] = Field(default_factory=list)
    explanation: str
    flags: list[Flag] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    ticket_id: str | None = None
    latency_ms: float = 0.0
    # Optional additions so the dashboard can render a timeline row from one event.
    step: int | None = None
    tool: ToolName | None = None
    args_masked: dict[str, Any] | None = None
    would_verdict: Verdict | None = None
    taint: Classification | None = None
    strikes: int | None = None


class AuditRecord(BaseModel):
    """Section 2.3, SQLite row."""

    seq: int
    ts: datetime
    action_id: str
    session_id: str
    scenario_id: str
    step: int
    mode: GatewayMode
    task: str
    tool: ToolName
    args_masked: dict[str, Any]
    matched_rules: list[str]
    verdict: Verdict
    status: ExecStatus
    would_verdict: Verdict | None = None
    explanation: str
    llm_explanation: str = ""
    flags: list[Flag]
    taint: Classification
    strikes: int
    result_masked: dict[str, Any] | None = None
    error: str | None = None
    latency_ms: float
    prev_hash: str
    hash: str


class ReviewTicket(BaseModel):
    """Section 2.4."""

    ticket_id: str
    action_id: str
    session_id: str
    created_at: datetime
    deadline: datetime | None = None
    risk: Risk
    urgency: Urgency
    rule_id: str
    impact_if_approved: str
    impact_if_rejected: str
    recent_actions: list[str] = Field(default_factory=list)
    state: TicketState = TicketState.pending
    decided_by: str | None = None
    decided_at: datetime | None = None
    # Optional additions so the inbox can show the action without a second call.
    tool: ToolName | None = None
    args_masked: dict[str, Any] | None = None
    flags: list[Flag] = Field(default_factory=list)
    explanation: str | None = None


class SessionRecord(BaseModel):
    """Section 2.5. Fingerprints are SHA-256 hashes, never raw values."""

    session_id: str
    scenario_id: str
    mode: GatewayMode
    scope: TaskScope
    taint: Classification = Classification.public
    fingerprints: set[str] = Field(default_factory=set)
    untrusted_content_seen: bool = False
    strikes: int = 0
    state: SessionState = SessionState.active
    denied_rules: list[str] = Field(default_factory=list)


class LiveEvent(BaseModel):
    """Section 2.6, SSE on /events."""

    type: LiveEventType
    session_id: str
    mode: GatewayMode
    payload: Decision | ReviewTicket | SessionRecord | dict[str, Any]


# Policy file, section 4.1


class RuleMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: ToolName | list[ToolName] | None = None
    classification: Classification | None = None
    path_glob: str | None = None
    recipient: Literal["internal", "external"] | None = None
    table: str | list[str] | None = None
    # Added: separates a new report from an overwrite.
    target_exists: bool | None = None
    # Added: expresses R-TOOL-REGISTRY.
    unregistered_tool: bool | None = None


class RuleWhen(BaseModel):
    model_config = ConfigDict(extra="forbid")

    taint_at_least: Classification | None = None
    content_match: Verdict | None = None
    no_content_match: Verdict | None = None
    # Added: expresses R-SEND-EXTERNAL-CLEAN.
    taint_below: Classification | None = None
    # Added: expresses R-UNTRUSTED-ACTION.
    untrusted_seen: bool | None = None
    # Added: expresses R-STRIKES.
    watch_at: int | None = None
    freeze_at: int | None = None


class PolicyDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    no_match: Literal[Verdict.REVIEW]
    on_error: Literal[Verdict.BLOCK]


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: RuleKind
    description: str
    rationale: str
    risk: Risk
    match: RuleMatch
    when: RuleWhen | None = None
    verdict: Verdict | None = None

    @field_validator("id")
    @classmethod
    def id_has_prefix(cls, value: str) -> str:
        if not value.startswith("R-"):
            raise ValueError("rule id must start with R-")
        return value

    @model_validator(mode="after")
    def keys_fit_kind(self) -> "PolicyRule":
        if self.when is not None and self.kind not in (RuleKind.flow, RuleKind.escalation):
            raise ValueError(f"{self.id}: `when` is for flow and escalation rules only")
        # The spec limits `verdict` to tool_access and resource_access. Flow rules
        # also need it, because R-SEND-INTERNAL is a flow rule that gives ALLOW.
        if self.verdict is not None and self.kind not in (
            RuleKind.tool_access,
            RuleKind.resource_access,
            RuleKind.flow,
        ):
            raise ValueError(f"{self.id}: `verdict` is not allowed on {self.kind.value} rules")
        return self


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    internal_domains: list[str]
    sensitive_fields: list[str]
    defaults: PolicyDefaults
    # Added: the Rulebook classifies tables, and taint depends on it.
    table_classification: dict[str, Classification] = Field(default_factory=dict)
    rules: list[PolicyRule]

    @model_validator(mode="after")
    def ids_are_unique(self) -> "PolicyFile":
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


# Scenario file, section 4.3


class ScenarioStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: ToolName
    args: dict[str, Any]
    is_violation: bool | None
    expected: Verdict
    expected_rule: str | None = None
    expected_flags: list[Flag] = Field(default_factory=list)
    note: str | None = None


class ScenarioSession(BaseModel):
    """One session of a multi-session scenario. Only K2 uses this."""

    model_config = ConfigDict(extra="forbid")

    scope: TaskScope
    steps: list[ScenarioStep]


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    category: ScenarioCategory
    brief_test: str
    scope: TaskScope | None = None
    reviewer: dict[int, Literal["approve", "reject", "late_approve"]] = Field(default_factory=dict)
    steps: list[ScenarioStep] | None = None
    sessions: list[ScenarioSession] | None = None
    llm_prompt: str | None = None

    @model_validator(mode="after")
    def single_or_multi_session(self) -> "Scenario":
        single = self.scope is not None and self.steps is not None
        multi = self.sessions is not None and self.scope is None and self.steps is None
        if single == multi:
            raise ValueError(f"{self.id}: use `scope` and `steps`, or `sessions`, not both")
        return self


# API response shapes, added at setup so the gateway, agent and dashboard agree.


class OutboxEmail(BaseModel):
    """One entry from GET /outbox. Body is masked."""

    email_id: str
    mode: GatewayMode
    session_id: str
    to: str
    subject: str
    body: str
    sent_at: datetime


class ScenarioSummary(BaseModel):
    """One entry from GET /scenarios."""

    id: str
    short_id: str
    title: str
    category: ScenarioCategory
    brief_test: str
    task: str
    has_llm_prompt: bool = False


class RunSession(BaseModel):
    session_id: str
    mode: GatewayMode


class RunStarted(BaseModel):
    """Response from POST /runs."""

    run_id: str
    scenario_id: str
    sessions: list[RunSession]


class StepResult(BaseModel):
    step: int
    tool: ToolName
    is_violation: bool | None
    expected: Verdict
    actual: Verdict
    status: ExecStatus
    matched_rules: list[str] = Field(default_factory=list)
    flags: list[Flag] = Field(default_factory=list)
    latency_ms: float = 0.0
    passed: bool


class ScenarioResult(BaseModel):
    scenario_id: str
    title: str
    category: ScenarioCategory
    mode: GatewayMode
    passed: bool
    attack_succeeded: bool | None = None
    steps: list[StepResult]
    detail: str = ""


class Ratio(BaseModel):
    numerator: int
    denominator: int
    value: float | None


class EvalMetrics(BaseModel):
    """The seven metrics from PRD section 8, for one mode."""

    mode: GatewayMode
    attack_success_rate: Ratio
    detection_precision: Ratio
    detection_recall: Ratio
    false_block_rate: Ratio
    legitimate_task_completion: Ratio
    latency_p50_ms: float | None
    latency_p95_ms: float | None
    execution_integrity: Ratio


class KnownMiss(BaseModel):
    scenario_id: str
    title: str
    leaked: bool
    why: str
    future_fix: str


class EvalReport(BaseModel):
    """GET /eval/report/{id}. Status is `running` until the file is complete."""

    report_id: str
    status: Literal["running", "complete", "failed"]
    generated_at: datetime | None = None
    with_llm: bool = False
    metrics: list[EvalMetrics] = Field(default_factory=list)
    scenarios: list[ScenarioResult] = Field(default_factory=list)
    known_misses: list[KnownMiss] = Field(default_factory=list)
    checks: dict[str, bool] = Field(default_factory=dict)
    error: str | None = None
