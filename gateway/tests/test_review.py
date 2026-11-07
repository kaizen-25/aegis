"""REVIEW tickets, parking, late approval and the approval re-check."""
import sqlite3
from datetime import timedelta

import pytest

from contracts.enums import ExecStatus, Flag, SessionState, TicketState, Verdict
from gateway.errors import ApiError

from .conftest import Driver, broad_scope


def overwrite(drv):
    return drv.do("report.write", {"name": "q3_board_report", "content": "Refreshed."})


def report_text(gw):
    return (gw.sandbox / "files" / "reports" / "q3_board_report.md").read_text()


def test_review_creates_pending_ticket_and_does_not_run(gw):
    drv = Driver(gw)
    before = report_text(gw)
    d = overwrite(drv)
    assert (d.verdict, d.status, d.matched_rules[0]) == (Verdict.REVIEW, ExecStatus.PENDING, "R-APPROVE-OVERWRITE")
    t, _ = gw.get_ticket(d.ticket_id)
    assert t.state is TicketState.pending and t.risk.value == "medium"
    assert t.rule_id == "R-APPROVE-OVERWRITE" and t.action_id == d.action_id
    assert t.deadline - t.created_at == timedelta(minutes=60)
    assert "q3_board_report" in t.impact_if_approved and "replaces" in t.impact_if_approved
    assert t.impact_if_rejected
    assert t.tool.value == "report.write" and t.args_masked["name"] == "q3_board_report"
    assert report_text(gw) == before and gw.audit.executions() == []


def test_deadlines_by_risk(gw):
    drv = Driver(gw, broad_scope(allowed_paths=["public/*"]))
    low = drv.do("db.query", {"table": "vendors", "filter": {}})            # R-DEFAULT, medium
    scope = drv.do("file.read", {"path": "internal/q3_plan.md"})            # R-SCOPE, medium
    high = drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})  # high
    assert gw.get_ticket(low.ticket_id)[0].deadline is not None
    assert gw.get_ticket(scope.ticket_id)[0].deadline is not None
    t = gw.get_ticket(high.ticket_id)[0]
    assert t.risk.value == "high" and t.deadline is None


def test_recent_actions_is_last_ten(gw):
    drv = Driver(gw)
    ids = [drv.do("file.read", {"path": "public/product_faq.md"}).action_id for _ in range(12)]
    d = overwrite(drv)
    assert gw.get_ticket(d.ticket_id)[0].recent_actions == ids[-10:]


def test_expired_ticket_is_parked_never_approved(gw):
    drv = Driver(gw)
    d = overwrite(drv)
    gw.clock.advance(59)
    assert gw.get_ticket(d.ticket_id)[0].state is TicketState.pending
    gw.clock.advance(2)
    t, _ = gw.get_ticket(d.ticket_id)
    assert t.state is TicketState.parked
    assert drv.session.state is SessionState.suspended
    assert gw.audit.executions() == []
    assert report_text(gw) != "Refreshed."
    statuses = [r["status"] for r in gw.audit.list(session_id=drv.sid)]
    assert statuses == ["PENDING", "PARKED"]
    assert [x.ticket_id for x in gw.list_tickets({"parked"})] == [d.ticket_id]


def test_high_risk_never_expires(gw):
    drv = Driver(gw)
    d = drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})
    gw.clock.advance(60 * 24 * 365)
    assert gw.get_ticket(d.ticket_id)[0].state is TicketState.pending


def test_late_approval_reruns_rules_then_executes(gw):
    drv = Driver(gw)
    d = overwrite(drv)
    gw.clock.advance(61)
    assert gw.get_ticket(d.ticket_id)[0].state is TicketState.parked
    out = gw.decide(d.ticket_id, True, "scripted-reviewer")
    assert out.status is ExecStatus.EXECUTED and out.result["overwritten"] is True
    assert report_text(gw) == "Refreshed."
    t, final = gw.get_ticket(d.ticket_id)
    assert t.state is TicketState.approved and t.decided_by == "scripted-reviewer" and t.decided_at
    assert final.status is ExecStatus.EXECUTED
    assert drv.session.state is SessionState.active          # returns to active after the decision
    assert [r["status"] for r in gw.audit.list(session_id=drv.sid)] == ["PENDING", "PARKED", "APPROVED", "EXECUTED"]
    assert gw.audit.executions() == [d.action_id]
    assert gw.audit.verify() == (True, None)


def test_reject_writes_rejected_and_does_not_run(gw):
    drv = Driver(gw)
    d = overwrite(drv)
    out = gw.decide(d.ticket_id, False, "human")
    assert out.status is ExecStatus.REJECTED
    assert report_text(gw) != "Refreshed." and gw.audit.executions() == []
    assert [r["status"] for r in gw.audit.list(session_id=drv.sid)] == ["PENDING", "REJECTED"]


def test_decided_ticket_cannot_be_decided_twice(gw):
    drv = Driver(gw)
    d = overwrite(drv)
    gw.decide(d.ticket_id, False, "human")
    for approve in (True, False):
        with pytest.raises(ApiError) as e:
            gw.decide(d.ticket_id, approve, "human")
        assert e.value.status == 409


def test_unknown_ticket_is_404(gw):
    with pytest.raises(ApiError) as e:
        gw.decide("tkt-nope", True, "x")
    assert e.value.status == 404


def test_same_rule_asking_again_counts_as_satisfied(gw):
    drv = Driver(gw)
    d = drv.do("db.query", {"table": "vendors", "filter": {}})
    out = gw.decide(d.ticket_id, True, "human")
    assert out.status is ExecStatus.EXECUTED and out.result["count"] == 4


def test_recheck_fails_when_a_new_block_appears(gw):
    drv = Driver(gw)
    d = drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})
    # While the ticket waits, the session accumulates three strikes and freezes.
    for _ in range(3):
        drv.do("file.read", {"path": "restricted/api_keys.txt"})
    assert drv.session.state is SessionState.frozen
    out = gw.decide(d.ticket_id, True, "human")
    assert (out.verdict, out.status) == (Verdict.BLOCK, ExecStatus.BLOCKED)
    assert out.matched_rules == ["R-STRIKES"]
    assert gw.audit.executions() == []
    count = sqlite3.connect(gw.sandbox / "novacorp.db").execute(
        "SELECT COUNT(*) FROM customers WHERE customer_id='NC-CUST-1002'").fetchone()[0]
    assert count == 1
    assert gw.get_ticket(d.ticket_id)[0].state is TicketState.rejected
    statuses = [r["status"] for r in gw.audit.list(session_id=drv.sid)]
    assert statuses[-1] == "BLOCKED" and "APPROVED" not in statuses and "EXECUTED" not in statuses
    assert drv.session.state is SessionState.frozen            # not silently reactivated
    with pytest.raises(ApiError):
        gw.decide(d.ticket_id, True, "human")


def test_recheck_fails_when_a_policy_block_appears_for_the_action(gw):
    """A review that was fine at ticket time now hits a prohibited rule."""
    drv = Driver(gw, broad_scope(allowed_paths=["public/*"]))
    d = drv.do("file.read", {"path": "misc/notes.txt"})   # R-SCOPE + default? scope only -> REVIEW
    assert d.verdict is Verdict.REVIEW
    entry = gw.tickets[d.ticket_id]
    entry.args["path"] = "restricted/api_keys.txt"          # simulate a changed situation
    out = gw.decide(d.ticket_id, True, "human")
    assert out.verdict is Verdict.BLOCK and out.matched_rules[0] == "R-PROHIBIT-RESTRICTED"
    assert gw.audit.executions() == []
    assert drv.session.strikes == 1


def test_recheck_fails_when_a_new_review_rule_is_added(gw):
    drv = Driver(gw)
    d = drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})
    drv.session.untrusted_content_seen = True               # an injected document was read meanwhile
    out = gw.decide(d.ticket_id, True, "human")
    assert out.status is ExecStatus.REJECTED and out.verdict is Verdict.REVIEW
    assert "R-UNTRUSTED-ACTION" in out.matched_rules
    assert gw.audit.executions() == []
    assert gw.get_ticket(d.ticket_id)[0].state is TicketState.rejected


def test_recheck_fails_closed_if_draft_vanishes(gw):
    drv = Driver(gw)
    drv.session.untrusted_content_seen = True
    d = drv.do("email.send", {"draft_id": drv.draft("team@novacorp.local")})
    assert d.verdict is Verdict.REVIEW
    gw.drafts.clear()
    out = gw.decide(d.ticket_id, True, "human")
    assert out.status is ExecStatus.FAIL_CLOSED and Flag.SYSTEM_FAIL_CLOSED in out.flags
    assert d.action_id not in gw.audit.executions()


def test_late_approval_uses_current_state_content_match(gw):
    """A send that was REVIEW (no match) becomes BLOCK if fingerprints now match."""
    drv = Driver(gw)
    drv.do("db.query", {"table": "customers", "filter": {"customer_id": "NC-CUST-1002"}})
    draft = drv.draft("vendor@partnerco.com", "the customer is Arjun")
    d = drv.do("email.send", {"draft_id": draft})
    assert d.verdict is Verdict.REVIEW
    # the draft is edited in place to contain the customer's email before approval
    gw.drafts[draft].body = "arjun.malhotra@examplemail.test"
    out = gw.decide(d.ticket_id, True, "human")
    assert out.verdict is Verdict.BLOCK and Flag.CONTENT_MATCH in out.flags
    assert gw.outbox() == []


def test_approved_send_writes_outbox_once(gw):
    drv = Driver(gw)
    drv.do("db.query", {"table": "customers", "filter": {"customer_id": "NC-CUST-1002"}})
    d = drv.do("email.send", {"draft_id": drv.draft("vendor@partnerco.com", "a premium customer")})
    assert d.verdict is Verdict.REVIEW and gw.outbox() == []
    out = gw.decide(d.ticket_id, True, "human")
    assert out.status is ExecStatus.EXECUTED
    assert len(gw.outbox()) == 1


def test_parked_session_returns_to_derived_state_after_decision(gw):
    drv = Driver(gw)
    drv.session.strikes = 2
    drv.session.state = SessionState.on_watch
    d = overwrite(drv)           # on watch + overwrite: REVIEW, medium
    gw.clock.advance(120)
    gw.get_ticket(d.ticket_id)
    assert drv.session.state is SessionState.suspended
    gw.decide(d.ticket_id, False, "human")
    assert drv.session.state is SessionState.on_watch
