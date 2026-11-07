"""Plain records produced by the runner and consumed by metrics. No HTTP in here."""
from __future__ import annotations

from dataclasses import dataclass, field

from contracts.enums import ExecStatus, Flag, GatewayMode, ScenarioCategory, ToolName, Verdict


@dataclass
class ReviewOutcome:
    """What the scripted reviewer did for one ticket."""

    action: str  # approve | reject | late_approve
    defaulted: bool = False  # True when the scenario named no action and reject was used
    decision_verdict: Verdict | None = None
    decision_status: ExecStatus | None = None
    parked_confirmed: bool | None = None
    executed_while_parked: bool | None = None
    error: str | None = None


@dataclass
class ReviewRequest:
    scenario_id: str
    session_id: str
    session_index: int
    step: int
    ticket_id: str
    action_id: str
    planned: str | None  # what the scenario's reviewer map says for this step


@dataclass
class StepRecord:
    session_index: int
    step: int
    tool: ToolName
    is_violation: bool | None
    expected: Verdict
    expected_rule: str | None
    action_id: str
    verdict: Verdict  # verdict returned by /actions/propose
    status: ExecStatus  # status returned by /actions/propose
    would_verdict: Verdict | None = None
    matched_rules: list[str] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    latency_ms: float = 0.0
    ticket_id: str | None = None
    ticket_state: str | None = None  # last state the agent saw: pending|parked|approved|rejected
    review: ReviewOutcome | None = None
    result: dict | None = None

    @property
    def stopped(self) -> bool:
        """Protected mode stopped the action (BLOCK or REVIEW)."""
        return self.verdict in (Verdict.BLOCK, Verdict.REVIEW)

    @property
    def executed_without_human(self) -> bool:
        return self.status == ExecStatus.EXECUTED

    @property
    def human_approved(self) -> bool:
        if self.review is not None and self.review.action in ("approve", "late_approve"):
            return self.review.decision_status is not None
        return self.ticket_state == "approved"

    @property
    def effective_status(self) -> ExecStatus:
        """Final status of the step after any review."""
        if self.review is not None and self.review.decision_status is not None:
            return self.review.decision_status
        mapping = {
            "approved": ExecStatus.APPROVED,
            "rejected": ExecStatus.REJECTED,
            "parked": ExecStatus.PARKED,
            "pending": ExecStatus.PENDING,
        }
        if self.ticket_state in mapping:
            return mapping[self.ticket_state]
        return self.status


@dataclass
class ScenarioRun:
    scenario_id: str
    title: str
    category: ScenarioCategory
    mode: GatewayMode
    session_ids: list[str]
    steps: list[StepRecord]

    @property
    def short_id(self) -> str:
        return self.scenario_id.split("-")[0]
