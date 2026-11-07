"""Stub gateway on port 8001, only so the agent can be tested before the real gateway exists.

Verdicts are read from each scenario's `expected` field. Nothing here enforces policy,
so results obtained against this stub are NOT real scores.

    python -m agent.stub_gateway
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agent.scenarios import find_scenario, load_all, scenario_sessions
from contracts.enums import ExecStatus, GatewayMode, Risk, TicketState, ToolName, Urgency, Verdict
from contracts.models import ActionRequest, Decision, Scenario, ReviewTicket

STUB_PORT = 8001


def _err(status: int, message: str, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, "code": code})


class StubState:
    def __init__(self, scenarios: list[Scenario]):
        self.scenarios = scenarios
        self.lock = threading.Lock()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.tickets: dict[str, ReviewTicket] = {}
        self.ticket_steps: dict[str, tuple[ActionRequest, Verdict]] = {}
        self.executions: list[dict[str, str]] = []
        self.audit: list[dict[str, Any]] = []
        self.clock_offset = timedelta(0)
        self.draft_counter = 0

    def now(self) -> datetime:
        return datetime.now(timezone.utc) + self.clock_offset


def _result_for(state: StubState, request: ActionRequest) -> dict[str, Any]:
    tool = request.tool
    if tool == ToolName.email_draft:
        state.draft_counter += 1
        return {"draft_id": f"draft-{state.draft_counter}"}
    if tool == ToolName.file_read:
        return {"path": request.args.get("path"), "content": "stub file content"}
    if tool == ToolName.db_query:
        return {"rows": [], "count": 0}
    if tool == ToolName.db_delete:
        return {"deleted": 1}
    if tool == ToolName.email_send:
        return {"sent": True}
    return {"written": request.args.get("name")}


def create_app(scenarios: list[Scenario] | None = None) -> FastAPI:
    state = StubState(scenarios if scenarios is not None else load_all())
    app = FastAPI(title="Aegis stub gateway")

    def record_execution(action_id: str, session_id: str, tool: str) -> None:
        state.executions.append({"action_id": action_id, "session_id": session_id, "tool": tool})

    @app.get("/health")
    def health():
        return {"ok": True, "ollama_available": False, "model": None, "stub": True}

    @app.post("/sessions")
    def create_session(body: dict):
        try:
            scenario = find_scenario(str(body.get("scenario_id", "")), state.scenarios)
        except Exception:
            return _err(404, "unknown scenario", "unknown_scenario")
        task = (body.get("scope") or {}).get("task")
        index = next(
            (i for i, (scope, _) in enumerate(scenario_sessions(scenario)) if scope.task == task), None
        )
        if index is None:
            return _err(422, "scope does not match the scenario", "bad_scope")
        mode = GatewayMode(body.get("mode", "protected"))
        session_id = f"stub-{uuid.uuid4().hex[:12]}"
        with state.lock:
            state.sessions[session_id] = {"scenario": scenario, "index": index, "mode": mode}
        return {"session_id": session_id}

    @app.post("/actions/propose")
    def propose(request: ActionRequest):
        started = time.perf_counter()
        with state.lock:
            session = state.sessions.get(request.session_id)
            action_id = str(uuid.uuid4())
            fail = lambda why: Decision(  # noqa: E731
                action_id=action_id,
                verdict=Verdict.BLOCK,
                status=ExecStatus.FAIL_CLOSED,
                explanation=why,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            if session is None:
                return fail("unknown session")
            steps = scenario_sessions(session["scenario"])[session["index"]][1]
            if not 1 <= request.step <= len(steps) or steps[request.step - 1].tool != request.tool:
                return fail("step does not match the scenario")
            step = steps[request.step - 1]
            mode: GatewayMode = session["mode"]
            expected = step.expected
            result = None
            ticket_id = None
            if mode == GatewayMode.passthrough:
                verdict, status, would = Verdict.ALLOW, ExecStatus.EXECUTED, expected
            else:
                would = None
                verdict = expected
                status = {
                    Verdict.ALLOW: ExecStatus.EXECUTED,
                    Verdict.BLOCK: ExecStatus.BLOCKED,
                    Verdict.REVIEW: ExecStatus.PENDING,
                }[expected]
            if status == ExecStatus.EXECUTED:
                result = _result_for(state, request)
                record_execution(action_id, request.session_id, request.tool.value)
            if status == ExecStatus.PENDING:
                ticket_id = f"tkt-{uuid.uuid4().hex[:10]}"
                high = request.tool == ToolName.db_delete
                created = state.now()
                state.tickets[ticket_id] = ReviewTicket(
                    ticket_id=ticket_id,
                    action_id=action_id,
                    session_id=request.session_id,
                    created_at=created,
                    deadline=None if high else created + timedelta(minutes=60),
                    risk=Risk.high if high else Risk.medium,
                    urgency=Urgency.normal,
                    rule_id=step.expected_rule or "R-DEFAULT-NO-MATCH",
                    impact_if_approved="stub",
                    impact_if_rejected="stub",
                    tool=request.tool,
                )
                state.ticket_steps[ticket_id] = (request, expected)
            state.audit.append({"action_id": action_id, "session_id": request.session_id, "verdict": verdict.value, "status": status.value})
            return Decision(
                action_id=action_id,
                verdict=verdict,
                status=status,
                matched_rules=[step.expected_rule] if step.expected_rule else [],
                explanation="stub verdict taken from the scenario's expected value",
                flags=list(step.expected_flags),
                result=result,
                ticket_id=ticket_id,
                latency_ms=(time.perf_counter() - started) * 1000,
                step=request.step,
                tool=request.tool,
                would_verdict=would,
            )

    @app.get("/tickets/{ticket_id}")
    def get_ticket(ticket_id: str):
        with state.lock:
            ticket = state.tickets.get(ticket_id)
            if ticket is None:
                return _err(404, "no such ticket", "ticket_not_found")
            return ticket

    @app.post("/tickets/{ticket_id}/decision")
    def decide(ticket_id: str, body: dict):
        with state.lock:
            ticket = state.tickets.get(ticket_id)
            if ticket is None:
                return _err(404, "no such ticket", "ticket_not_found")
            if ticket.state not in (TicketState.pending, TicketState.parked):
                return _err(409, "ticket already decided", "ticket_closed")
            approve = bool(body.get("approve"))
            ticket.decided_by = str(body.get("by", ""))
            ticket.decided_at = state.now()
            started = time.perf_counter()
            if approve:
                ticket.state = TicketState.approved
                request, _ = state.ticket_steps[ticket_id]
                new_id = str(uuid.uuid4())
                record_execution(new_id, ticket.session_id, request.tool.value)
                return Decision(
                    action_id=new_id,
                    verdict=Verdict.ALLOW,
                    status=ExecStatus.EXECUTED,
                    explanation="stub: approved and executed after re-check",
                    result=_result_for(state, request),
                    latency_ms=(time.perf_counter() - started) * 1000,
                )
            ticket.state = TicketState.rejected
            return Decision(
                action_id=ticket.action_id,
                verdict=Verdict.REVIEW,
                status=ExecStatus.REJECTED,
                explanation="stub: rejected by reviewer",
                latency_ms=(time.perf_counter() - started) * 1000,
            )

    @app.post("/clock/advance")
    def advance(body: dict):
        with state.lock:
            state.clock_offset += timedelta(minutes=float(body.get("minutes", 0)))
            now = state.now()
            for ticket in state.tickets.values():
                if ticket.state == TicketState.pending and ticket.deadline and ticket.deadline <= now:
                    ticket.state = TicketState.parked
            return {"now": now.isoformat()}

    @app.post("/sandbox/reset")
    def reset():
        # Like the real contract: files, DB and outboxes only. The execution log stays.
        return {"ok": True}

    @app.get("/audit")
    def audit():
        with state.lock:
            return list(state.audit)

    @app.get("/audit/executions")
    def executions():
        with state.lock:
            return list(state.executions)

    return app


class StubHandle:
    def __init__(self, server: uvicorn.Server, thread: threading.Thread):
        self._server = server
        self._thread = thread

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


def start_in_thread(port: int = STUB_PORT, scenarios: list[Scenario] | None = None) -> StubHandle:
    """Start the stub on 127.0.0.1:<port> in a background thread and wait until it answers."""
    import httpx

    config = uvicorn.Config(create_app(scenarios), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health", timeout=1).status_code == 200:
                return StubHandle(server, thread)
        except httpx.HTTPError:
            time.sleep(0.1)
    server.should_exit = True
    raise RuntimeError(f"stub gateway did not start on port {port}")


if __name__ == "__main__":
    uvicorn.run(create_app(), host="127.0.0.1", port=STUB_PORT, log_level="info")
