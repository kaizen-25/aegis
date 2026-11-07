"""The gateway: the only code that may execute a tool.

Flow for every proposed action (Rulebook section 1): validate, normalize, session gate, collect
matches, scope check, combine, act, record. Any exception on that path becomes a BLOCK /
FAIL_CLOSED Decision. `Gateway.execute()` is the single place a tool handler is called.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from contracts.enums import (
    Classification,
    ExecStatus,
    Flag,
    GatewayMode,
    LiveEventType,
    Risk,
    SessionState,
    TicketState,
    ToolName,
    Urgency,
    Verdict,
)
from contracts.models import (
    ActionRequest,
    Decision,
    LiveEvent,
    ReviewTicket,
    Scenario,
    SessionRecord,
    TaskScope,
)
from gateway import content, engine, seed, tools
from gateway.audit import AuditStore
from gateway.engine import (
    Evaluation,
    Facts,
    R_FAIL_CLOSED,
    R_FAIL_CLOSED_TEXT,
    R_LLM,
    R_LLM_TEXT,
    RuleHit,
    max_taint,
    taint_rank,
)
from gateway.errors import ApiError, FailClosed, ToolError
from gateway.events import EventBus
from gateway.masking import Masker
from gateway.observer import CONSEQUENTIAL_TOOLS, Explainer, ExplainerWorker, Observer, ObserverResult
from gateway.normalize import classify_path, email_domain
from gateway.policy import LoadedPolicy, load_policy, load_scenarios, resolve_scenario_id
from gateway.schemas import validate_and_normalize

log = logging.getLogger("aegis.gateway")

REVIEW_WINDOW_MINUTES = {Risk.low: 15, Risk.medium: 60, Risk.high: None}
FLAG_ORDER = list(Flag)


class Clock:
    """Wall clock plus an offset, so the eval can move time forward for scenario T1."""

    def __init__(self) -> None:
        self.offset = timedelta(0)

    def now(self) -> datetime:
        return datetime.now(timezone.utc) + self.offset

    def advance(self, minutes: float) -> datetime:
        self.offset += timedelta(minutes=minutes)
        return self.now()

    def reset(self) -> None:
        self.offset = timedelta(0)


@dataclass
class Prepared:
    """A validated, normalized action with everything the engine and the ticket need."""

    tool: ToolName
    args: dict[str, Any]  # normalized, raw values (kept in memory only)
    facts: Facts
    args_masked: dict[str, Any]


@dataclass
class TicketEntry:
    ticket: ReviewTicket
    step: int
    tool: ToolName
    args: dict[str, Any]
    review_rules: set[str]
    flags: set[Flag]
    final: Decision | None = None


@dataclass
class ExecOutcome:
    ok: bool
    result: dict[str, Any] | None = None
    error: str | None = None
    tool_ms: float = 0.0


def _clip(value: Any, limit: int = 300) -> Any:
    """Shorten long strings inside already-masked data before it goes into an LLM prompt."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "..."
    if isinstance(value, dict):
        return {k: _clip(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v, limit) for v in value]
    return value


def _sorted_flags(flags: set[Flag]) -> list[Flag]:
    return sorted(flags, key=FLAG_ORDER.index)


class Gateway:
    def __init__(
        self,
        sandbox_dir: Path,
        audit_path: Path,
        policy_path: Path,
        scenarios_dir: Path,
        clock: Clock | None = None,
        bus: EventBus | None = None,
        observer: Observer | None = None,
        explainer: Explainer | None = None,
    ) -> None:
        self.sandbox = Path(sandbox_dir)
        self.loaded: LoadedPolicy = load_policy(policy_path)
        self.policy_path = Path(policy_path)
        self.scenarios: dict[str, Scenario] = load_scenarios(scenarios_dir)
        self.audit = AuditStore(audit_path)
        self.clock = clock or Clock()
        self.bus = bus or EventBus()
        self.masker = Masker.from_seed(seed.CUSTOMERS, seed.CANARIES)
        self.internal_domains = {d.lower() for d in self.loaded.policy.internal_domains}
        self.table_class = {t.lower(): c for t, c in self.loaded.policy.table_classification.items()}
        self.lock = threading.RLock()
        self.sessions: dict[str, SessionRecord] = {}
        self.tickets: dict[str, TicketEntry] = {}
        self.drafts: dict[str, tools.Draft] = {}
        self.recent: dict[str, list[str]] = {}
        # Optional LLM helpers. Off unless a session asks for them (observer_sessions), and never
        # used for passthrough sessions. The flag lives here, not in the frozen SessionRecord.
        self.observer = observer
        self.explainer = explainer
        self.observer_sessions: set[str] = set()
        self.history: dict[str, list[dict[str, Any]]] = {}  # masked summaries of the last 10 actions
        self.explain_worker = ExplainerWorker(self._explain_job)
        if not (self.sandbox / "novacorp.db").exists():
            seed.reset(self.sandbox)

    # ------------------------------------------------------------------ sessions

    def create_session(self, scenario_id: str, scope: TaskScope | None, mode: GatewayMode,
                       observer: bool = False) -> SessionRecord:
        with self.lock:
            resolved = resolve_scenario_id(self.scenarios, scenario_id) or scenario_id
            if scope is None:
                scenario = self.scenarios.get(resolved)
                if scenario is None:
                    raise ApiError(422, "missing_scope", "scope is required for an unknown scenario")
                scope = (scenario.scope or scenario.sessions[0].scope)  # type: ignore[index]
            session = SessionRecord(session_id=f"sess-{uuid.uuid4().hex[:12]}", scenario_id=resolved,
                                    mode=mode, scope=scope)
            self.sessions[session.session_id] = session
            if observer and mode is GatewayMode.protected:
                self.observer_sessions.add(session.session_id)
            self._persist(session)
            self._emit_session(session)
            return session

    def get_session(self, session_id: str) -> SessionRecord:
        session = self.sessions.get(session_id)
        if session is None:
            raise ApiError(404, "not_found", "unknown session")
        return session

    @staticmethod
    def public_session(session: SessionRecord) -> SessionRecord:
        """Session as shown outside the gateway: fingerprints are never exposed."""
        return session.model_copy(update={"fingerprints": set()})

    def unfreeze(self, session_id: str, by: str) -> SessionRecord:
        with self.lock:
            session = self.get_session(session_id)
            session.strikes = 0
            session.denied_rules = []
            session.state = SessionState.active
            self._persist(session)
            self._emit_session(session)
            return self.public_session(session)

    def _derive_state(self, session: SessionRecord) -> SessionState:
        if session.strikes >= self.loaded.freeze_at:
            return SessionState.frozen
        if session.strikes >= self.loaded.watch_at:
            return SessionState.on_watch
        return SessionState.active

    def _persist(self, session: SessionRecord) -> None:
        try:
            self.audit.save_session(session.session_id, session.model_dump_json())
        except Exception:  # noqa: BLE001 - mirroring is best effort, memory is the source
            log.exception("could not mirror session")

    # ------------------------------------------------------------------ events

    def _emit(self, type_: LiveEventType, session: SessionRecord | None, payload: Any,
              session_id: str | None = None, mode: GatewayMode | None = None) -> None:
        try:
            self.bus.publish(LiveEvent(
                type=type_,
                session_id=session.session_id if session else (session_id or "unknown"),
                mode=session.mode if session else (mode or GatewayMode.protected),
                payload=payload,
            ))
        except Exception:  # noqa: BLE001 - a dashboard problem must never affect enforcement
            log.exception("could not publish event")

    def _emit_session(self, session: SessionRecord) -> None:
        self._emit(LiveEventType.session_update, session, self.public_session(session))

    # ------------------------------------------------------------------ propose

    def propose(self, raw: Any) -> Decision:
        """Entry point for POST /actions/propose. Never raises; every failure is a BLOCK."""
        started = time.perf_counter()
        action_id = str(uuid.uuid4())
        try:
            hint = self._observe(raw)  # may call the local LLM; deliberately outside the lock
            with self.lock:
                return self._propose(raw, action_id, started, hint)
        except Exception as exc:  # noqa: BLE001 - invariant 2: any exception fails closed
            return self.fail_closed(raw, action_id, exc, started)

    def fail_closed(self, raw: Any, action_id: str | None, reason: Exception | str,
                    started: float | None = None) -> Decision:
        """Build, record and publish a BLOCK / FAIL_CLOSED Decision. Never raises."""
        started = started if started is not None else time.perf_counter()
        action_id = action_id or str(uuid.uuid4())
        detail = reason if isinstance(reason, str) else (
            str(reason) if isinstance(reason, FailClosed) else f"internal error ({type(reason).__name__})")
        try:
            detail = self.masker.mask_text(detail)[:300]
        except Exception:  # noqa: BLE001
            detail = "internal error"
        decision = Decision(
            action_id=action_id, verdict=Verdict.BLOCK, status=ExecStatus.FAIL_CLOSED,
            matched_rules=[R_FAIL_CLOSED], explanation=R_FAIL_CLOSED_TEXT, flags=[Flag.SYSTEM_FAIL_CLOSED],
            error=detail, latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        session = None
        try:
            body = raw if isinstance(raw, dict) else {}
            sid = body.get("session_id") if isinstance(body.get("session_id"), str) else "unknown"
            session = self.sessions.get(sid)
            sid = self.masker.mask_text(sid[:100])  # unvalidated input: it may carry a sensitive value
            tool = body.get("tool") if isinstance(body.get("tool"), str) else "unknown"
            tool = self.masker.mask_text(tool)
            step = body.get("step") if isinstance(body.get("step"), int) and not isinstance(body.get("step"), bool) else 0
            args = self.masker.mask(body.get("args")) if isinstance(body.get("args"), dict) else {}
            if len(json.dumps(args, default=str)) > 20_000:
                args = {"_truncated": True}
            decision.step = step
            decision.args_masked = args
            if session is not None:
                decision.taint, decision.strikes = session.taint, session.strikes
            self._write_audit(
                decision, session_id=sid, scenario_id=session.scenario_id if session else "unknown",
                mode=session.mode if session else GatewayMode.protected, task=session.scope.task if session else "",
                tool=tool[:100], step=step, args_masked=args,
                taint=session.taint if session else Classification.public,
                strikes=session.strikes if session else 0)
            self._emit(LiveEventType.decision, session, decision, session_id=sid)
        except Exception:  # noqa: BLE001
            log.exception("could not record fail-closed decision")
        return decision

    def _propose(self, raw: Any, action_id: str, started: float, hint: ObserverResult | None = None) -> Decision:
        # Step 1: validate. The body is validated here, inside the fail-closed wrapper.
        if not isinstance(raw, dict):
            raise FailClosed("request body must be a JSON object")
        try:
            request = ActionRequest.model_validate(raw)
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) or "body" for e in exc.errors()})
            raise FailClosed(f"invalid action request: {', '.join(fields)}") from None
        session = self.sessions.get(request.session_id)
        if session is None:
            raise FailClosed("unknown session (missing context)")
        # Steps 1 (args) and 2: schema validation and normalization.
        prepared = self._prepare(session, request.tool, request.args)
        # Steps 3 to 6: session gate, matches, scope, combine.
        evaluation = engine.evaluate(self.loaded, session, prepared.facts)
        # Step 7: optional LLM observer. Its answer was fetched before taking the lock and is applied
        # only through engine.tighten(), so it can turn ALLOW into REVIEW and nothing else.
        reason = self._apply_observer(session, prepared, evaluation, hint)
        flags = set(evaluation.flags)
        if request.agent_note and content.has_urgency(request.agent_note):
            flags.add(Flag.URGENCY_CLAIM)  # a flag only; urgency itself comes from scope
        return self._act(session, request, prepared, evaluation, flags, action_id, started, reason)

    # ------------------------------------------------------------------ LLM observer

    def _llm_context(self, session: SessionRecord, prepared: Prepared, ev: Evaluation) -> dict[str, Any]:
        """Masked data only: never raw values."""
        return {
            "task": self.masker.mask_text(session.scope.task),
            "proposed_action": {"tool": prepared.tool.value, "args": _clip(prepared.args_masked)},
            "rules_verdict": ev.verdict.value,
            "matched_rules": ev.matched_rules,
            "session_taint": session.taint.value,
            "recent_actions": list(self.history.get(session.session_id, [])),
        }

    def _observe(self, raw: Any) -> ObserverResult | None:
        """Pre-pass: consult the observer only for a protected, observer-enabled session, a
        consequential tool, and a rules verdict of ALLOW. Never raises; None means no opinion.

        The model call runs without holding the gateway lock, so a slow model (3 s cap) does not
        stall other sessions. The authoritative evaluation is repeated under the lock afterwards.
        """
        obs = self.observer
        if obs is None or not isinstance(raw, dict):
            return None
        sid, tool = raw.get("session_id"), raw.get("tool")
        if not isinstance(sid, str) or sid not in self.observer_sessions or tool not in CONSEQUENTIAL_TOOLS:
            return None
        try:
            with self.lock:
                session = self.sessions.get(sid)
                if session is None or session.mode is not GatewayMode.protected:
                    return None
                request = ActionRequest.model_validate(raw)
                prepared = self._prepare(session, request.tool, request.args)
                ev = engine.evaluate(self.loaded, session, prepared.facts)
                if ev.verdict is not Verdict.ALLOW:
                    return None  # BLOCK and REVIEW are never sent to the model
                context = self._llm_context(session, prepared, ev)
            return obs.review(context)
        except Exception:  # noqa: BLE001
            return None

    def _apply_observer(self, session: SessionRecord, prepared: Prepared, ev: Evaluation,
                        hint: ObserverResult | None) -> str | None:
        """Fold the observer's answer into `ev`. Returns the (masked) reason if it raised a concern."""
        if (hint is None or not hint.concern or ev.verdict is not Verdict.ALLOW
                or session.mode is not GatewayMode.protected
                or session.session_id not in self.observer_sessions
                or prepared.tool.value not in CONSEQUENTIAL_TOOLS):
            return None
        if engine.tighten(ev.verdict, Verdict.REVIEW) is not Verdict.REVIEW:
            return None  # the only way to change a verdict is tighten()
        ev.hits.append(RuleHit(R_LLM, Verdict.REVIEW, Risk.medium, R_LLM_TEXT,
                               "The optional local model can raise a flag, never lower one",
                               len(self.loaded.policy.rules) + 2, {Flag.LLM_CONCERN}, True))
        ev.hits.sort(key=lambda h: (-engine.STRICTNESS[h.verdict], h.order))
        ev.verdict = Verdict.REVIEW
        ev.flags.add(Flag.LLM_CONCERN)
        return self.masker.mask_text(hint.reason)[:200]

    # ------------------------------------------------------------------ LLM explainer

    def _queue_explanation(self, session: SessionRecord, prepared: Prepared, d: Decision,
                           observer_reason: str | None) -> None:
        # An observer concern already carries the model's own reason, so it is not explained twice.
        if (self.explainer is None or session.session_id not in self.observer_sessions
                or d.verdict not in (Verdict.BLOCK, Verdict.REVIEW) or observer_reason):
            return
        context = {
            "task": self.masker.mask_text(session.scope.task),
            "action": {"tool": prepared.tool.value, "args": _clip(prepared.args_masked)},
            "winning_rule": d.matched_rules[0] if d.matched_rules else None,
            "rule_text": d.explanation,
            "other_rules": d.matched_rules[1:],
            "flags": [f.value for f in d.flags],
            "session_taint": session.taint.value,
        }
        self.explain_worker.submit({
            "action_id": d.action_id, "session_id": session.session_id, "mode": session.mode,
            "outcome": "blocked" if d.verdict is Verdict.BLOCK else "sent to a human for review",
            "context": context,
        })

    def _explain_job(self, job: dict[str, Any]) -> None:
        """Runs on the background worker. Silent on any failure."""
        if self.explainer is None:
            return
        text = self.explainer.explain(job["context"], job["outcome"])
        if not text:
            return
        self._publish_llm_text(job["action_id"], job["session_id"], job["mode"], self.masker.mask_text(text))

    def _publish_llm_text(self, action_id: str, session_id: str, mode: GatewayMode, text: str) -> None:
        # Filled in after the row exists; llm_explanation is excluded from the audit hash.
        if self.audit.set_llm_explanation(action_id, text):
            self._emit(LiveEventType.explanation_ready, None,
                       {"action_id": action_id, "llm_explanation": text}, session_id=session_id, mode=mode)

    # ------------------------------------------------------------------ preparing

    def _prepare(self, session: SessionRecord, tool: ToolName, raw_args: Any) -> Prepared:
        args = validate_and_normalize(tool, raw_args, tools.list_tables(self.sandbox))
        facts = Facts(tool=tool.value)
        margs = self.masker.mask(args)
        if tool is ToolName.file_read:
            facts.path = args["path"]
            cls = classify_path(args["path"])
            facts.classification = Classification(cls) if cls else None
        elif tool is ToolName.report_write:
            facts.target_exists = (self.sandbox / "files" / "reports" / f"{args['name']}.md").exists()
        elif tool in (ToolName.db_query, ToolName.db_delete):
            facts.table = args["table"]
            facts.classification = self.table_class.get(args["table"])
        elif tool is ToolName.email_draft:
            facts.recipient = args["to"]
            facts.recipient_kind = self._recipient_kind(args["to"])
        elif tool is ToolName.email_send:
            draft = self.drafts.get(args["draft_id"])
            if draft is None or draft.session_id != session.session_id:
                raise FailClosed("no such draft in this session (missing context)")
            if draft.sent:
                raise FailClosed("draft was already sent")
            facts.recipient = draft.to
            facts.recipient_kind = self._recipient_kind(draft.to)
            # Layer two of leak detection: compare the draft's values with stored fingerprints.
            facts.content_match = content.content_matches(f"{draft.subject}\n{draft.body}", session.fingerprints)
            margs = self.masker.mask({**args, "to": draft.to, "subject": draft.subject, "body": draft.body})
        return Prepared(tool, args, facts, margs)

    def _recipient_kind(self, address: str) -> str:
        # Exact match only: no suffix or subdomain matching, so lookalike domains are external.
        return "internal" if email_domain(address) in self.internal_domains else "external"

    # ------------------------------------------------------------------ acting

    def _act(self, session: SessionRecord, request: ActionRequest, prepared: Prepared,
             ev: Evaluation, flags: set[Flag], action_id: str, started: float,
             observer_reason: str | None = None) -> Decision:
        protected = session.mode is GatewayMode.protected
        winner = ev.winner

        # Strikes: a policy rule giving the final BLOCK counts, in both modes, never once frozen.
        if ev.policy_block:
            session.strikes += 1
            session.denied_rules.append(winner.rule_id)
            if session.state is not SessionState.frozen:
                session.state = self._derive_state(session)

        verdict = ev.verdict
        would = None if protected else ev.verdict
        ticket: ReviewTicket | None = None
        outcome: ExecOutcome | None = None

        if protected and verdict is Verdict.BLOCK:
            status = ExecStatus.BLOCKED
        elif protected and verdict is Verdict.REVIEW:
            status = ExecStatus.PENDING
            ticket = self._open_ticket(session, request, prepared, ev, flags, action_id)
        else:
            outcome = self.execute(session, prepared, action_id)
            flags |= self._after_execution(session, prepared, outcome)
            status = ExecStatus.EXECUTED if outcome.ok else ExecStatus.EXECUTION_FAILED
            if not protected:
                verdict = Verdict.ALLOW  # passthrough always executes

        decision = self._decision(session, prepared, action_id, verdict, status, ev, flags, outcome,
                                  ticket.ticket_id if ticket else None, would, started)
        decision.step = request.step
        self._record(session, request.step, prepared, decision)
        self.recent.setdefault(session.session_id, []).append(action_id)
        hist = self.history.setdefault(session.session_id, [])
        hist.append({"tool": prepared.tool.value, "args": _clip(prepared.args_masked, 120),
                     "verdict": decision.verdict.value, "status": decision.status.value})
        del hist[:-10]
        self._persist(session)
        self._emit(LiveEventType.decision, session, decision)
        if ticket is not None:
            self._emit(LiveEventType.ticket, session, ticket)
        self._emit_session(session)
        if observer_reason:
            self._publish_llm_text(action_id, session.session_id, session.mode, f"Observer: {observer_reason}")
        self._queue_explanation(session, prepared, decision, observer_reason)
        return decision

    def _decision(self, session: SessionRecord, prepared: Prepared, action_id: str, verdict: Verdict,
                  status: ExecStatus, ev: Evaluation, flags: set[Flag], outcome: ExecOutcome | None,
                  ticket_id: str | None, would: Verdict | None, started: float,
                  explanation: str | None = None) -> Decision:
        tool_ms = outcome.tool_ms if outcome else 0.0
        result = None
        error = None
        if outcome is not None:
            result = self._safe_mask(outcome.result) if outcome.ok else None
            error = self.masker.mask_text(outcome.error) if outcome.error else None
        return Decision(
            action_id=action_id, verdict=verdict, status=status, matched_rules=ev.matched_rules,
            explanation=explanation or ev.winner.description, flags=_sorted_flags(flags), result=result,
            error=error, ticket_id=ticket_id,
            latency_ms=round(max(0.0, (time.perf_counter() - started) * 1000 - tool_ms), 3),
            tool=prepared.tool, args_masked=prepared.args_masked, would_verdict=would,
            taint=session.taint, strikes=session.strikes,
        )

    def _safe_mask(self, value: Any) -> Any:
        try:
            return self.masker.mask(value)
        except Exception:  # noqa: BLE001 - never return an unmasked result
            log.exception("masking failed")
            return {"_error": "result withheld: masking failed"}

    # ------------------------------------------------------------------ execution

    def execute(self, session: SessionRecord, prepared: Prepared, action_id: str) -> ExecOutcome:
        """THE single call site of a tool handler (invariant 1).

        Callers reach this only for an ALLOW verdict, a passthrough run, or a human-approved
        REVIEW that passed the re-check in `decide()`. The action id is recorded in the
        executions table immediately before the handler runs, so the eval can prove that no
        BLOCKED action ever got here.
        """
        self.audit.record_execution(action_id, self.clock.now().isoformat())
        env = tools.ToolEnv(self.sandbox, session.session_id, session.mode.value, self.clock.now(), self.drafts)
        handler = tools.HANDLERS[prepared.tool]
        began = time.perf_counter()
        try:
            result = handler(env, prepared.args)
            return ExecOutcome(True, result, None, (time.perf_counter() - began) * 1000)
        except ToolError as exc:
            return ExecOutcome(False, None, str(exc), (time.perf_counter() - began) * 1000)
        except Exception as exc:  # noqa: BLE001 - a tool crash is a tool failure, not a policy outcome
            log.exception("tool handler crashed")
            return ExecOutcome(False, None, f"tool error ({type(exc).__name__})", (time.perf_counter() - began) * 1000)

    def _after_execution(self, session: SessionRecord, prepared: Prepared, outcome: ExecOutcome) -> set[Flag]:
        """Update taint, fingerprints and the untrusted-content marker. Only after a handler ran."""
        flags: set[Flag] = set()
        if not outcome.ok or outcome.result is None:
            return flags  # a failed tool read nothing, so nothing taints the session
        try:
            facts = prepared.facts
            fields = self.loaded.policy.sensitive_fields
            if prepared.tool is ToolName.file_read:
                text = outcome.result.get("content", "")
                if facts.classification is not None:
                    session.taint = max_taint(session.taint, facts.classification)
                if facts.classification is Classification.confidential:
                    session.fingerprints |= content.fingerprints_from_text(text, fields)
                if content.has_injection(text):
                    session.untrusted_content_seen = True
                    flags.add(Flag.UNTRUSTED_CONTENT)
                if content.has_urgency(text):
                    flags.add(Flag.URGENCY_CLAIM)
            elif prepared.tool is ToolName.db_query:
                if facts.classification is not None:
                    session.taint = max_taint(session.taint, facts.classification)
                    if taint_rank(facts.classification) >= taint_rank(Classification.confidential):
                        session.fingerprints |= content.fingerprints_from_rows(outcome.result.get("rows", []), fields)
        except Exception:  # noqa: BLE001 - if tracking fails, assume the worst
            log.exception("session tracking failed after execution")
            session.taint = max_taint(session.taint, Classification.confidential)
            session.untrusted_content_seen = True
        return flags

    # ------------------------------------------------------------------ audit

    def _record(self, session: SessionRecord, step: int, prepared: Prepared, d: Decision,
                scenario_id: str | None = None) -> None:
        self._write_audit(d, session_id=session.session_id, scenario_id=scenario_id or session.scenario_id,
                          mode=session.mode, task=session.scope.task, tool=prepared.tool.value, step=step,
                          args_masked=prepared.args_masked, taint=session.taint, strikes=session.strikes)

    def _write_audit(self, d: Decision, *, session_id: str, scenario_id: str, mode: GatewayMode, task: str,
                     tool: str, step: int, args_masked: dict[str, Any], taint: Classification,
                     strikes: int) -> None:
        try:
            self.audit.append({
                "ts": self.clock.now().isoformat(), "action_id": d.action_id, "session_id": session_id,
                "scenario_id": scenario_id, "step": step, "mode": mode.value,
                "task": self.masker.mask_text(task), "tool": tool, "args_masked": args_masked,
                "matched_rules": d.matched_rules, "verdict": d.verdict.value, "status": d.status.value,
                "would_verdict": d.would_verdict.value if d.would_verdict else None,
                "explanation": d.explanation, "llm_explanation": "",
                "flags": [f.value for f in d.flags], "taint": taint.value, "strikes": strikes,
                "result_masked": d.result, "error": d.error, "latency_ms": d.latency_ms,
            })
        except Exception:  # noqa: BLE001 - see module docstring: the tool may already have run
            log.exception("could not write audit record")

    # ------------------------------------------------------------------ tickets

    def _open_ticket(self, session: SessionRecord, request: ActionRequest, prepared: Prepared,
                     ev: Evaluation, flags: set[Flag], action_id: str) -> ReviewTicket:
        winner = ev.winner
        now = self.clock.now()
        minutes = REVIEW_WINDOW_MINUTES[winner.risk]
        approved, rejected = self._impact(prepared)
        ticket = ReviewTicket(
            ticket_id=f"tkt-{uuid.uuid4().hex[:10]}", action_id=action_id, session_id=session.session_id,
            created_at=now, deadline=now + timedelta(minutes=minutes) if minutes else None,
            risk=winner.risk, urgency=session.scope.urgency, rule_id=winner.rule_id,
            impact_if_approved=approved, impact_if_rejected=rejected,
            recent_actions=self.recent.get(session.session_id, [])[-10:],
            state=TicketState.pending, tool=prepared.tool, args_masked=prepared.args_masked,
            flags=_sorted_flags(flags), explanation=winner.description,
        )
        self.tickets[ticket.ticket_id] = TicketEntry(
            ticket=ticket, step=request.step, tool=prepared.tool, args=prepared.args,
            review_rules=ev.review_rule_ids, flags=set(flags))
        return ticket

    @staticmethod
    def _impact(p: Prepared) -> tuple[str, str]:
        a = p.args_masked
        if p.tool is ToolName.file_read:
            return (f"The agent reads '{a['path']}' and its contents become visible to this session.",
                    "The file is not read; the task continues without it.")
        if p.tool is ToolName.report_write:
            replace = " It replaces the existing report." if p.facts.target_exists else ""
            return (f"Report '{a['name']}' is saved to reports/.{replace}",
                    "Nothing is written" + (" and the existing report stays unchanged." if p.facts.target_exists else "."))
        if p.tool is ToolName.db_query:
            return (f"Rows from table '{a['table']}' matching {json.dumps(a['filter'], ensure_ascii=False)} "
                    "are returned to the agent.", "No rows are returned; the task continues without them.")
        if p.tool is ToolName.db_delete:
            return (f"Record {a['record_id']} is permanently deleted from table '{a['table']}'.",
                    "The record stays in the table.")
        if p.tool is ToolName.email_send:
            return (f"An email to {a['to']} (subject: '{a['subject']}') is written to the outbox.",
                    "Nothing is sent; the draft stays unsent.")
        return (f"{p.tool.value} runs with the arguments shown.", f"{p.tool.value} does not run.")

    def _expire(self) -> None:
        """Lazy expiry: a pending ticket past its deadline is parked. Never approved."""
        now = self.clock.now()
        for entry in list(self.tickets.values()):
            t = entry.ticket
            if t.state is TicketState.pending and t.deadline is not None and now >= t.deadline:
                t.state = TicketState.parked
                session = self.sessions.get(t.session_id)
                if session is not None and session.state in (SessionState.active, SessionState.on_watch):
                    session.state = SessionState.suspended
                    self._persist(session)
                self._write_ticket_audit(entry, Verdict.REVIEW, ExecStatus.PARKED, entry.ticket.rule_id,
                                         "Review window expired; the action is parked and was not approved")
                self._emit(LiveEventType.ticket_update, session, t, session_id=t.session_id)
                if session is not None:
                    self._emit_session(session)

    def _write_ticket_audit(self, entry: TicketEntry, verdict: Verdict, status: ExecStatus, rule_id: str,
                            explanation: str, matched: list[str] | None = None,
                            flags: set[Flag] | None = None) -> Decision:
        t = entry.ticket
        session = self.sessions.get(t.session_id)
        d = Decision(
            action_id=t.action_id, verdict=verdict, status=status, matched_rules=matched or [rule_id],
            explanation=explanation, flags=_sorted_flags(flags if flags is not None else entry.flags),
            ticket_id=t.ticket_id, tool=entry.tool, args_masked=t.args_masked,
            taint=session.taint if session else None, strikes=session.strikes if session else None)
        if session is not None:
            self._write_audit(d, session_id=session.session_id, scenario_id=session.scenario_id,
                              mode=session.mode, task=session.scope.task, tool=entry.tool.value,
                              step=entry.step, args_masked=t.args_masked or {}, taint=session.taint,
                              strikes=session.strikes)
        return d

    def get_ticket(self, ticket_id: str) -> tuple[ReviewTicket, Decision | None]:
        with self.lock:
            self._expire()
            entry = self.tickets.get(ticket_id)
            if entry is None:
                raise ApiError(404, "not_found", "unknown ticket")
            return entry.ticket, entry.final

    def list_tickets(self, states: set[str] | None = None) -> list[ReviewTicket]:
        with self.lock:
            self._expire()
            items = [e.ticket for e in self.tickets.values()]
            if states:
                items = [t for t in items if t.state.value in states]
            return items

    def decide(self, ticket_id: str, approve: bool, by: str) -> Decision:
        started = time.perf_counter()
        with self.lock:
            self._expire()
            entry = self.tickets.get(ticket_id)
            if entry is None:
                raise ApiError(404, "not_found", "unknown ticket")
            ticket = entry.ticket
            if ticket.state in (TicketState.approved, TicketState.rejected):
                raise ApiError(409, "already_decided", f"ticket already {ticket.state.value}")
            session = self.sessions.get(ticket.session_id)
            if session is None:
                raise ApiError(409, "session_gone", "the session for this ticket no longer exists")
            ticket.decided_by = by
            ticket.decided_at = self.clock.now()

            if not approve:
                ticket.state = TicketState.rejected
                d = self._write_ticket_audit(entry, Verdict.REVIEW, ExecStatus.REJECTED, ticket.rule_id,
                                             f"Rejected by {by}")
                return self._finish_decision(session, entry, d)

            # Late or not, an approval never executes on its own authority.
            #
            # RE-CHECK RULE (read this closely). Approving a ticket re-runs the full rule evaluation
            # against the session as it is NOW, not as it was when the ticket was opened. The action
            # executes unless the re-run gives BLOCK, or adds a REVIEW rule that the original ticket
            # did not contain. The SAME rule asking for review again counts as satisfied: that is
            # the rule the human just answered, and without this, scenario T1 (overwrite a report,
            # approve after the window closed) could never finish. A different or additional REVIEW
            # rule means the situation changed (for example the session went on watch, or untrusted
            # content was read since), so the human's answer does not cover it. In that case, and on
            # any BLOCK, nothing runs, the failure is recorded, and the Decision explains why.
            try:
                prepared = self._prepare(session, entry.tool, entry.args)
                ev = engine.evaluate(self.loaded, session, prepared.facts)
            except Exception as exc:  # noqa: BLE001 - a failed re-check fails closed
                ticket.state = TicketState.rejected
                reason = str(exc) if isinstance(exc, FailClosed) else f"internal error ({type(exc).__name__})"
                d = self._write_ticket_audit(
                    entry, Verdict.BLOCK, ExecStatus.FAIL_CLOSED, R_FAIL_CLOSED,
                    R_FAIL_CLOSED_TEXT, flags={Flag.SYSTEM_FAIL_CLOSED})
                d.error = self.masker.mask_text(reason)[:300]
                return self._finish_decision(session, entry, d)

            added = ev.review_rule_ids - entry.review_rules
            if ev.verdict is Verdict.BLOCK or added:
                ticket.state = TicketState.rejected
                if ev.policy_block:
                    session.strikes += 1
                    session.denied_rules.append(ev.winner.rule_id)
                    if session.state is not SessionState.frozen:
                        session.state = self._derive_state(session)
                if ev.verdict is Verdict.BLOCK:
                    status, why = ExecStatus.BLOCKED, f"Approval by {by} not applied: re-check gave BLOCK ({ev.winner.rule_id})"
                else:
                    status, why = ExecStatus.REJECTED, (
                        f"Approval by {by} not applied: re-check added review rule(s) {', '.join(sorted(added))}")
                d = self._write_ticket_audit(entry, ev.verdict, status, ev.winner.rule_id, why,
                                             matched=ev.matched_rules, flags=entry.flags | ev.flags)
                return self._finish_decision(session, entry, d)

            # Re-check passed. Audit APPROVED first, then execute and record the outcome.
            ticket.state = TicketState.approved
            self._write_ticket_audit(entry, Verdict.REVIEW, ExecStatus.APPROVED, ticket.rule_id,
                                     f"Approved by {by}; re-check passed", matched=ev.matched_rules)
            outcome = self.execute(session, prepared, ticket.action_id)
            flags = set(entry.flags) | self._after_execution(session, prepared, outcome)
            status = ExecStatus.EXECUTED if outcome.ok else ExecStatus.EXECUTION_FAILED
            d = self._decision(session, prepared, ticket.action_id, Verdict.REVIEW, status, ev, flags, outcome,
                               ticket.ticket_id, None, started,
                               explanation=f"Approved by {by}; {ev.winner.description}")
            self._record(session, entry.step, prepared, d)
            return self._finish_decision(session, entry, d, audited=True)

    def _finish_decision(self, session: SessionRecord, entry: TicketEntry, d: Decision,
                         audited: bool = False) -> Decision:
        """Common tail of a decision: restore a parked session, publish events, keep the outcome."""
        if session.state is SessionState.suspended and not any(
                e.ticket.state is TicketState.parked and e.ticket.session_id == session.session_id
                for e in self.tickets.values()):
            session.state = self._derive_state(session)
        entry.final = d
        d.step = entry.step
        d.strikes, d.taint = session.strikes, session.taint
        self._persist(session)
        self._emit(LiveEventType.ticket_update, session, entry.ticket)
        self._emit(LiveEventType.decision, session, d)
        self._emit_session(session)
        return d

    # ------------------------------------------------------------------ admin

    def reset(self, clear_audit: bool = False) -> None:
        with self.lock:
            seed.reset(self.sandbox)
            self.sessions.clear()
            self.tickets.clear()
            self.drafts.clear()
            self.recent.clear()
            self.observer_sessions.clear()
            self.history.clear()
            self.explain_worker.drain()
            self.clock.reset()
            self.audit.clear_sessions()
            if clear_audit:
                self.audit.clear_all()

    def complete_sessions(self, session_ids: list[str]) -> None:
        """An agent process ended. Display only: `completed` changes no rule and no verdict.

        Frozen and suspended sessions keep their state, and a session cleared by a reset is ignored.
        """
        with self.lock:
            for session_id in session_ids:
                session = self.sessions.get(session_id)
                if session is None or session.state not in (SessionState.active, SessionState.on_watch):
                    continue
                session.state = SessionState.completed
                self._persist(session)
                self._emit_session(session)

    def outbox(self, mode: GatewayMode | None = None) -> list[dict[str, Any]]:
        modes = [mode.value] if mode else ["protected", "passthrough"]
        emails: list[dict[str, Any]] = []
        for m in modes:
            folder = self.sandbox / "outbox" / m
            if not folder.is_dir():
                continue
            for file in sorted(folder.glob("*.json")):
                try:
                    data = json.loads(file.read_text(encoding="utf-8"))
                    emails.append({
                        "email_id": data["email_id"], "mode": m, "session_id": data["session_id"],
                        "to": self.masker.mask_text(data["to"]), "subject": self.masker.mask_text(data["subject"]),
                        "body": self.masker.mask_text(data["body"]), "sent_at": data["sent_at"],
                    })
                except (OSError, ValueError, KeyError):
                    continue
        emails.sort(key=lambda e: e["sent_at"])
        return emails


__all__ = ["Gateway", "Clock", "Urgency"]
