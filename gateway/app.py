"""FastAPI application factory for the Aegis gateway. gateway/main.py holds the instance."""
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette import EventSourceResponse, ServerSentEvent
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from contracts.enums import AgentKind, GatewayMode, TicketState
from contracts.models import (
    EvalReport,
    OutboxEmail,
    RunSession,
    RunStarted,
    TaskScope,
)
from gateway.core import Gateway
from gateway.engine import BUILTIN_RULES
from gateway.errors import ApiError
from gateway.observer import Explainer, Observer
from gateway.policy import resolve_scenario_id, summarize
from gateway.runs import RunManager

ROOT = Path(__file__).resolve().parents[1]
OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen2.5:7b-instruct-q4_K_M"
FALLBACK_MODEL = "qwen2.5:3b-instruct-q4_K_M"
MAX_BODY = 1_000_000
CORS_ORIGINS = ["http://127.0.0.1:5173", "http://localhost:5173"]
REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,80}$")


@dataclass
class Settings:
    sandbox_dir: Path = ROOT / "sandbox"
    audit_path: Path = ROOT / "gateway" / "data" / "audit.db"
    policy_path: Path = ROOT / "policies" / "novacorp.yaml"
    scenarios_dir: Path = ROOT / "scenarios"
    reports_dir: Path = ROOT / "reports_out"
    log_dir: Path = ROOT / "gateway" / "data" / "runs"
    gateway_url: str = "http://127.0.0.1:8000"
    python: str | None = None
    popen: Any = None
    # Optional LLM helpers. None builds the default Ollama-backed ones (still off per session).
    observer: Any = None
    explainer: Any = None


class SessionCreate(BaseModel):
    scenario_id: str
    scope: TaskScope | None = None
    mode: GatewayMode = GatewayMode.protected
    observer: bool = False


class DecisionBody(BaseModel):
    approve: bool
    by: str = "dashboard"


class ByBody(BaseModel):
    by: str = "dashboard"


class RunBody(BaseModel):
    scenario_id: str
    agent_kind: AgentKind = AgentKind.scripted
    split: bool = False


class EvalBody(BaseModel):
    with_llm: bool = False


class ClockBody(BaseModel):
    minutes: float = Field(ge=0, le=525_600)


def probe_ollama() -> tuple[bool, str | None]:
    """Quick local probe with a short timeout. Everything works when this says no."""
    try:
        resp = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=0.4)
        names = {m.get("name") for m in resp.json().get("models", [])}
    except Exception:  # noqa: BLE001
        return False, None
    for candidate in (MODEL, FALLBACK_MODEL):
        if candidate in names:
            return True, candidate
    return True, None


def _err(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, "code": code})


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    # Both loaders raise on an invalid file, which stops the gateway from starting.
    gw = Gateway(cfg.sandbox_dir, cfg.audit_path, cfg.policy_path, cfg.scenarios_dir,
                 observer=cfg.observer or Observer(), explainer=cfg.explainer or Explainer())
    runs_kwargs: dict[str, Any] = {"python": cfg.python}
    if cfg.popen is not None:
        runs_kwargs["popen"] = cfg.popen
    runs = RunManager(ROOT, cfg.log_dir, cfg.gateway_url, **runs_kwargs)
    health_cache: dict[str, Any] = {"at": 0.0, "value": (False, None)}

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        runs.shutdown()

    app = FastAPI(title="Aegis Gateway", lifespan=lifespan)
    app.state.gateway = gw
    app.state.runs = runs
    app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])

    # ---------------------------------------------------------------- errors

    @app.exception_handler(ApiError)
    async def _api_error(_req: Request, exc: ApiError):
        return _err(exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_req: Request, exc: RequestValidationError):
        fields = sorted({".".join(str(p) for p in e["loc"][1:]) or "body" for e in exc.errors()})
        return _err(422, "validation_error", f"invalid request: {', '.join(fields)}")

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_req: Request, exc: StarletteHTTPException):
        return _err(exc.status_code, f"http_{exc.status_code}", str(exc.detail))

    @app.exception_handler(Exception)
    async def _unhandled(_req: Request, _exc: Exception):
        return _err(500, "internal_error", "internal error")

    def dump(model: Any) -> JSONResponse:
        return JSONResponse(content=jsonable_encoder(model))

    # ---------------------------------------------------------------- agent endpoints

    @app.post("/sessions")
    def create_session(body: SessionCreate):
        session = gw.create_session(body.scenario_id, body.scope, body.mode, body.observer)
        return {"session_id": session.session_id}

    @app.post("/actions/propose")
    async def propose(request: Request):
        # The raw body is validated inside the gateway's fail-closed wrapper: bad input is a
        # BLOCK / FAIL_CLOSED Decision with status 200, never a 422 or a 500.
        try:
            body = await request.body()
            if len(body) > MAX_BODY:
                raise ValueError("body too large")
            raw = json.loads(body.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return dump(await run_in_threadpool(gw.fail_closed, None, None, "malformed request body"))
        try:
            decision = await run_in_threadpool(gw.propose, raw)
        except Exception as exc:  # noqa: BLE001 - propose() should never raise; belt and braces
            decision = await run_in_threadpool(gw.fail_closed, raw, None, exc)
        return dump(decision)

    @app.get("/tickets/{ticket_id}")
    def get_ticket(ticket_id: str):
        ticket, final = gw.get_ticket(ticket_id)
        data = jsonable_encoder(ticket)
        if final is not None:
            data["decision"] = jsonable_encoder(final)  # extra key: lets the agent read the outcome
        return JSONResponse(content=data)

    # ---------------------------------------------------------------- dashboard endpoints

    @app.get("/events")
    async def events(_request: Request):
        sub = gw.bus.subscribe()

        async def stream():
            try:
                yield ServerSentEvent(comment="connected")
                while True:
                    kind, data = await sub.queue.get()
                    yield ServerSentEvent(data=data, event=kind)
            except asyncio.CancelledError:
                raise
            finally:
                gw.bus.unsubscribe(sub)

        return EventSourceResponse(stream(), ping=10)

    @app.get("/tickets")
    def list_tickets(state: str | None = None):
        states = None
        if state:
            states = {s.strip() for s in state.split(",") if s.strip()}
            valid = {s.value for s in TicketState}
            if not states <= valid:
                raise ApiError(422, "validation_error", "state must be a list of pending, parked, approved, rejected")
        return dump(gw.list_tickets(states))

    @app.post("/tickets/{ticket_id}/decision")
    def decide(ticket_id: str, body: DecisionBody):
        return dump(gw.decide(ticket_id, body.approve, body.by))

    @app.post("/sessions/{session_id}/unfreeze")
    def unfreeze(session_id: str, body: ByBody | None = None):
        return dump(gw.unfreeze(session_id, (body or ByBody()).by))

    @app.get("/sessions/{session_id}")
    def get_session(session_id: str):
        data = jsonable_encoder(gw.public_session(gw.get_session(session_id)))
        data["observer"] = session_id in gw.observer_sessions  # extra key, not part of SessionRecord
        return JSONResponse(content=data)

    @app.get("/audit")
    def audit(session_id: str | None = None, tool: str | None = None, verdict: str | None = None,
              rule: str | None = None, mode: str | None = None):
        return JSONResponse(content=gw.audit.list(session_id, tool, verdict, rule, mode))

    @app.get("/audit/verify")
    def audit_verify():
        ok, broken = gw.audit.verify()
        return {"ok": ok, "broken_at_seq": broken}

    @app.get("/audit/executions")
    def audit_executions():
        return gw.audit.executions()

    @app.get("/outbox")
    def outbox(mode: GatewayMode | None = None):
        return dump([OutboxEmail(**e) for e in gw.outbox(mode)])

    @app.get("/policy")
    def policy():
        loaded = gw.loaded
        policy_model = loaded.policy
        return {
            "yaml": loaded.raw_text,
            "rules": [r.model_dump(mode="json", exclude_none=True) for r in policy_model.rules],
            "builtin_rules": BUILTIN_RULES,
            "internal_domains": policy_model.internal_domains,
            "sensitive_fields": policy_model.sensitive_fields,
            "table_classification": {k: v.value for k, v in policy_model.table_classification.items()},
            "defaults": jsonable_encoder(policy_model.defaults),
        }

    @app.get("/scenarios")
    def scenarios():
        return dump([summarize(s) for s in gw.scenarios.values()])

    @app.get("/scenarios/{scenario_id}")
    def scenario(scenario_id: str):
        sid = resolve_scenario_id(gw.scenarios, scenario_id)
        if sid is None:
            raise ApiError(404, "not_found", "unknown scenario")
        return dump(gw.scenarios[sid])

    @app.post("/runs")
    def start_run(body: RunBody):
        sid = resolve_scenario_id(gw.scenarios, body.scenario_id)
        if sid is None:
            raise ApiError(404, "not_found", "unknown scenario")
        scenario_obj = gw.scenarios[sid]
        with runs.lock:
            if runs.busy():
                raise ApiError(409, "busy", "a run or evaluation is already active; decide its ticket in Review Inbox or press Reset")
            gw.reset()
            scopes = [scenario_obj.scope] if scenario_obj.sessions is None else [s.scope for s in scenario_obj.sessions]
            modes = [GatewayMode.passthrough, GatewayMode.protected] if body.split else [GatewayMode.protected]
            by_mode: dict[str, list[str]] = {}
            started: list[RunSession] = []
            for mode in modes:
                ids = []
                for scope in scopes:
                    session = gw.create_session(sid, scope, mode, observer=body.agent_kind is AgentKind.llm)
                    ids.append(session.session_id)
                    started.append(RunSession(session_id=session.session_id, mode=mode))
                by_mode[mode.value] = ids
            run_id = runs.start_run(sid, body.agent_kind.value, by_mode, on_exit=gw.complete_sessions)
        return dump(RunStarted(run_id=run_id, scenario_id=sid, sessions=started))

    @app.post("/eval/run")
    def start_eval(body: EvalBody | None = None):
        with runs.lock:
            if runs.busy():
                raise ApiError(409, "busy", "a run or evaluation is already active; decide its ticket in Review Inbox or press Reset")
            report_id = f"eval-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
            runs.start_eval(report_id, bool(body and body.with_llm))
        return {"report_id": report_id}

    @app.get("/eval/report/{report_id}")
    def eval_report(report_id: str):
        if report_id == "latest":
            report_id = runs.last_eval_id or _default_report(cfg.reports_dir)
            if report_id is None:
                raise ApiError(404, "not_found", "no evaluation has been run yet")
        if not REPORT_ID_RE.match(report_id):
            raise ApiError(422, "validation_error", "invalid report id")
        path = cfg.reports_dir / f"{report_id}.json"
        if path.is_file():
            try:
                return JSONResponse(content=json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass  # half-written file: treat as still running
        if runs.eval_known(report_id) and not runs.eval_running() and runs.eval_exit_code(report_id) is not None \
                and not path.is_file():
            return dump(EvalReport(report_id=report_id, status="failed",
                                   error=f"evaluation process exited with code {runs.eval_exit_code(report_id)}"))
        return dump(EvalReport(report_id=report_id, status="running"))

    @app.post("/sandbox/reset")
    def reset(clear_audit: bool = False):
        # Stop agent run processes first so a stuck run can never lock the operator out. The eval
        # process is left alone: it calls this endpoint between scenarios.
        with runs.lock:
            stopped = runs.terminate_runs()
            gw.reset(clear_audit=clear_audit)
        return {"ok": True, "audit_cleared": clear_audit, "runs_stopped": stopped}

    @app.post("/clock/advance")
    def clock_advance(body: ClockBody):
        with gw.lock:
            now = gw.clock.advance(body.minutes)
        return {"now": now.isoformat(), "offset_minutes": gw.clock.offset.total_seconds() / 60}

    @app.get("/clock")
    def clock_now():
        return {"now": gw.clock.now().isoformat(), "offset_minutes": gw.clock.offset.total_seconds() / 60}

    @app.get("/health")
    def health():
        now = time.monotonic()
        if now - health_cache["at"] > 5:
            health_cache["value"] = probe_ollama()
            health_cache["at"] = now
        available, model = health_cache["value"]
        return {"ok": True, "ollama_available": available, "model": model}

    return app


DEFAULT_REPORT_ID = "final"


def _default_report(directory: Path) -> str | None:
    """The report the Evaluation page opens with when this gateway has not started an eval itself:
    the pinned `final` report if it exists, so a test eval run from the CLI cannot replace it on screen,
    otherwise the newest report file."""
    if (directory / f"{DEFAULT_REPORT_ID}.json").is_file():
        return DEFAULT_REPORT_ID
    files = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime) if directory.is_dir() else []
    return files[-1].stem if files else None



