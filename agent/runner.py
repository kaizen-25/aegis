"""Scripted agent: replays a scenario through the gateway over HTTP.

The agent's only calls are POST /sessions, POST /actions/propose and GET /tickets/{id}.
It never decides a ticket; a separate reviewer (reviewer.py) does that. This module
must not import the reviewer or anything from the gateway.
"""
from __future__ import annotations

import time
from typing import Callable, Protocol

import httpx
from pydantic import ValidationError

from agent.records import ReviewOutcome, ReviewRequest, ScenarioRun, StepRecord
from agent.scenarios import ResolveContext, resolve, scenario_sessions
from contracts.enums import AgentKind, ExecStatus, GatewayMode, ToolName, Verdict
from contracts.models import ActionRequest, Decision, ReviewTicket, Scenario

DEFAULT_REVIEW_TIMEOUT_S = 60.0
HUMAN_REVIEW_TIMEOUT_S = 3600.0


class RunnerError(Exception):
    """The run could not be completed. `partial` holds what was recorded before the problem."""

    def __init__(self, message: str, partial: ScenarioRun | None = None):
        super().__init__(message)
        self.partial = partial


class ReviewHook(Protocol):
    """Implemented by the scripted reviewer. The runner only notifies it."""

    def on_review(self, request: ReviewRequest) -> None: ...

    def finish(self) -> dict[tuple[int, int], ReviewOutcome]: ...


def _error_text(response: httpx.Response) -> str:
    try:
        body = response.json()
        return f"HTTP {response.status_code} {body.get('code', '')} {body.get('error', '')}".strip()
    except ValueError:
        return f"HTTP {response.status_code} {response.text[:200]}"


class AgentClient:
    """The three calls the agent is allowed to make."""

    def __init__(self, base_url: str, client: httpx.Client | None = None):
        self._owns = client is None
        self.http = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=30.0)

    def close(self) -> None:
        if self._owns:
            self.http.close()

    def create_session(
        self, scenario_id: str, scope: dict, mode: GatewayMode, observer: bool = False
    ) -> str:
        body: dict = {"scenario_id": scenario_id, "scope": scope, "mode": mode.value}
        if observer:
            body["observer"] = True
        response = self.http.post("/sessions", json=body)
        if response.status_code >= 300:
            raise RunnerError(f"POST /sessions failed: {_error_text(response)}")
        session_id = response.json().get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise RunnerError("POST /sessions returned no session_id")
        return session_id

    def propose(self, request: ActionRequest) -> Decision:
        return self.propose_raw(request.model_dump(mode="json"))

    def propose_raw(self, body: dict) -> Decision:
        """Send a proposal as given. The live agent uses this so that a tool name the model
        made up still reaches the gateway, which fails it closed."""
        response = self.http.post("/actions/propose", json=body)
        if response.status_code >= 300:
            raise RunnerError(f"POST /actions/propose failed: {_error_text(response)}")
        try:
            return Decision.model_validate(response.json())
        except (ValidationError, ValueError) as exc:
            raise RunnerError(f"unreadable Decision from /actions/propose: {exc}") from exc

    def get_ticket_raw(self, ticket_id: str) -> dict:
        """The ticket as JSON, including the gateway's optional `decision` key once decided."""
        response = self.http.get(f"/tickets/{ticket_id}")
        if response.status_code >= 300:
            raise RunnerError(f"GET /tickets/{ticket_id} failed: {_error_text(response)}")
        try:
            body = response.json()
        except ValueError as exc:
            raise RunnerError(f"unreadable ticket {ticket_id}: {exc}") from exc
        if not isinstance(body, dict):
            raise RunnerError(f"unreadable ticket {ticket_id}")
        return body

    def get_ticket(self, ticket_id: str) -> ReviewTicket:
        response = self.http.get(f"/tickets/{ticket_id}")
        if response.status_code >= 300:
            raise RunnerError(f"GET /tickets/{ticket_id} failed: {_error_text(response)}")
        try:
            return ReviewTicket.model_validate(response.json())
        except (ValidationError, ValueError) as exc:
            raise RunnerError(f"unreadable ticket {ticket_id}: {exc}") from exc


def wait_for_ticket(
    client: AgentClient,
    ticket_id: str,
    *,
    poll_interval: float,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Poll until the ticket leaves `pending`. Returns the last state seen.

    `parked` ends the wait: the review window closed, and nothing may execute by timeout.
    """
    deadline = time.monotonic() + timeout
    while True:
        state = client.get_ticket(ticket_id).state.value
        if state != "pending":
            return state
        if time.monotonic() >= deadline:
            return "pending"
        sleep(poll_interval)


def run_scenario(
    scenario: Scenario,
    mode: GatewayMode,
    base_url: str,
    *,
    canaries: dict[str, str],
    session_ids: list[str] | None = None,
    agent_kind: AgentKind = AgentKind.scripted,
    reviewer: ReviewHook | None = None,
    poll_interval: float = 1.0,
    review_timeout: float = DEFAULT_REVIEW_TIMEOUT_S,
    http_client: httpx.Client | None = None,
    log: Callable[[str], None] | None = None,
    step_delay: float = 0.0,
    observer: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> ScenarioRun:
    """Run every step of every session.

    A rejected or parked step does not stop later steps, and a session that freezes still
    receives its remaining steps so the gateway records their BLOCK (D1 step 4).

    step_delay pauses after each step (for a watchable demo); it is never used while waiting
    for a ticket. observer=True asks the gateway to enable its LLM observer for the session.
    """
    if agent_kind != AgentKind.scripted:
        raise RunnerError("only the scripted agent is built; the llm agent is not built yet")
    sessions = scenario_sessions(scenario)
    if session_ids is not None and len(session_ids) != len(sessions):
        raise RunnerError(
            f"{scenario.id} has {len(sessions)} session(s) but {len(session_ids)} id(s) were given"
        )
    say = log or (lambda _msg: None)
    client = AgentClient(base_url, http_client)
    run = ScenarioRun(
        scenario_id=scenario.id,
        title=scenario.title,
        category=scenario.category,
        mode=mode,
        session_ids=[],
        steps=[],
    )
    problems: list[str] = []
    try:
        for s_index, (scope, steps) in enumerate(sessions):
            session_id = (
                session_ids[s_index]
                if session_ids is not None
                else client.create_session(scenario.id, scope.model_dump(mode="json"), mode, observer)
            )
            run.session_ids.append(session_id)
            ctx = ResolveContext(canaries=canaries)
            for number, step in enumerate(steps, start=1):
                args = resolve(step.args, ctx, strict=False)
                if ctx.unresolved:
                    problems.append(f"session {s_index + 1} step {number}: unresolved {ctx.unresolved}")
                    ctx.unresolved.clear()
                request = ActionRequest(
                    session_id=session_id,
                    step=number,
                    tool=step.tool,
                    args=args,
                    agent_kind=agent_kind,
                )
                try:
                    decision = client.propose(request)
                except RunnerError as exc:
                    problems.append(f"session {s_index + 1} step {number}: {exc}")
                    ctx.last_result = None
                    continue
                record = StepRecord(
                    session_index=s_index,
                    step=number,
                    tool=step.tool,
                    is_violation=step.is_violation,
                    expected=step.expected,
                    expected_rule=step.expected_rule,
                    action_id=decision.action_id,
                    verdict=decision.verdict,
                    status=decision.status,
                    would_verdict=decision.would_verdict,
                    matched_rules=list(decision.matched_rules),
                    flags=list(decision.flags),
                    latency_ms=decision.latency_ms,
                    ticket_id=decision.ticket_id,
                    result=decision.result,
                )
                say(f"  [{s_index + 1}.{number}] {step.tool.value} -> {decision.verdict.value} {decision.status.value}")
                if decision.verdict == Verdict.REVIEW and decision.ticket_id:
                    if reviewer is not None:
                        reviewer.on_review(
                            ReviewRequest(
                                scenario_id=scenario.id,
                                session_id=session_id,
                                session_index=s_index,
                                step=number,
                                ticket_id=decision.ticket_id,
                                action_id=decision.action_id,
                                planned=scenario.reviewer.get(number) if scenario.sessions is None else None,
                            )
                        )
                    try:
                        record.ticket_state = wait_for_ticket(
                            client,
                            decision.ticket_id,
                            poll_interval=poll_interval,
                            timeout=review_timeout,
                        )
                    except RunnerError as exc:
                        problems.append(f"session {s_index + 1} step {number}: {exc}")
                    say(f"      ticket {decision.ticket_id} -> {record.ticket_state}")
                # Only a step that really ran can feed the next placeholder.
                ctx.last_result = decision.result if decision.status == ExecStatus.EXECUTED else None
                if step.tool == ToolName.email_draft and decision.result:
                    draft = decision.result.get("draft_id")
                    if isinstance(draft, str):
                        ctx.last_draft = draft
                run.steps.append(record)
                if step_delay > 0:
                    sleep(step_delay)
    finally:
        client.close()

    if reviewer is not None:
        outcomes = reviewer.finish()
        for record in run.steps:
            outcome = outcomes.get((record.session_index, record.step))
            if outcome is not None:
                record.review = outcome
                if outcome.error:
                    problems.append(
                        f"session {record.session_index + 1} step {record.step}: reviewer error: {outcome.error}"
                    )
    if problems:
        raise RunnerError("; ".join(problems), partial=run)
    return run
