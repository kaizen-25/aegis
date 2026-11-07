"""Scripted reviewer: the only code that calls POST /tickets/{id}/decision.

It stands in for a human during evaluation, following the scenario's `reviewer` map.
Each ticket is handled on its own thread so the agent can poll the ticket meanwhile.
"""
from __future__ import annotations

import threading
import time

import httpx
from pydantic import ValidationError

from agent.admin import AdminError, fetch_execution_ids
from agent.records import ReviewOutcome, ReviewRequest
from contracts.models import Decision, ReviewTicket

REVIEWER_NAME = "scripted-reviewer"
LATE_MINUTES = 61


class ScriptedReviewer:
    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.Client | None = None,
        by: str = REVIEWER_NAME,
        park_wait_s: float = 10.0,
    ):
        self._owns = client is None
        self.http = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=30.0)
        self.by = by
        self.park_wait_s = park_wait_s
        self._threads: list[threading.Thread] = []
        self._outcomes: dict[tuple[int, int], ReviewOutcome] = {}
        self._lock = threading.Lock()

    # ReviewHook interface -------------------------------------------------

    def on_review(self, request: ReviewRequest) -> None:
        thread = threading.Thread(target=self._handle, args=(request,), daemon=True)
        self._threads.append(thread)
        thread.start()

    def finish(self) -> dict[tuple[int, int], ReviewOutcome]:
        for thread in self._threads:
            thread.join()
        self._threads.clear()
        with self._lock:
            outcomes = dict(self._outcomes)
            self._outcomes.clear()
        if self._owns:
            self.http.close()
        return outcomes

    # Internals --------------------------------------------------------------

    def _handle(self, request: ReviewRequest) -> None:
        action = request.planned or "reject"
        outcome = ReviewOutcome(action=action, defaulted=request.planned is None)
        try:
            if action == "late_approve":
                self._late_approve(request, outcome)
            else:
                self._decide(request.ticket_id, action == "approve", outcome)
        except (httpx.HTTPError, AdminError, ValidationError, ValueError, RuntimeError) as exc:
            outcome.error = f"{type(exc).__name__}: {exc}"
        with self._lock:
            self._outcomes[(request.session_index, request.step)] = outcome

    def _decide(self, ticket_id: str, approve: bool, outcome: ReviewOutcome) -> None:
        response = self.http.post(
            f"/tickets/{ticket_id}/decision", json={"approve": approve, "by": self.by}
        )
        if response.status_code >= 300:
            raise RuntimeError(f"decision on {ticket_id} failed: HTTP {response.status_code} {response.text[:200]}")
        decision = Decision.model_validate(response.json())
        outcome.decision_verdict = decision.verdict
        outcome.decision_status = decision.status

    def _ticket_state(self, ticket_id: str) -> str:
        response = self.http.get(f"/tickets/{ticket_id}")
        if response.status_code >= 300:
            raise RuntimeError(f"GET /tickets/{ticket_id} failed: HTTP {response.status_code}")
        return ReviewTicket.model_validate(response.json()).state.value

    def _late_approve(self, request: ReviewRequest, outcome: ReviewOutcome) -> None:
        """Leave the ticket unanswered, move the clock past the window, then approve late."""
        response = self.http.post("/clock/advance", json={"minutes": LATE_MINUTES})
        if response.status_code >= 300:
            raise RuntimeError(f"POST /clock/advance failed: HTTP {response.status_code} {response.text[:200]}")
        deadline = time.monotonic() + self.park_wait_s
        state = self._ticket_state(request.ticket_id)
        while state != "parked" and time.monotonic() < deadline:
            time.sleep(0.1)
            state = self._ticket_state(request.ticket_id)
        outcome.parked_confirmed = state == "parked"
        outcome.executed_while_parked = request.action_id in fetch_execution_ids(self.http)
        self._decide(request.ticket_id, True, outcome)
