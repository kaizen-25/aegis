"""Optional LLM observer and explainer, tested with fake clients. Nothing here needs Ollama."""
import json
import sqlite3
import time

import pytest

from contracts.enums import ExecStatus, Flag, GatewayMode, Verdict
from gateway.core import Gateway
from gateway.observer import Explainer, Observer, parse_observer_output

from .conftest import POLICY, SCENARIOS, Driver, broad_scope

PHONE = "+91 98765 43210"


class FakeLLM:
    """Callable transport: records every request, answers from `reply`."""

    def __init__(self, reply=None, delay=0.0, exc=None):
        self.reply = reply if reply is not None else json.dumps({"concern": False, "reason": "fine"})
        self.delay, self.exc = delay, exc
        self.calls = []

    def __call__(self, payload, timeout):
        self.calls.append(payload)
        if self.delay:
            time.sleep(self.delay)
        if self.exc:
            raise self.exc
        return {"message": {"content": self.reply}}


def concern(reason="looks off-task"):
    return json.dumps({"concern": True, "reason": reason})


def make_gw(tmp_path, obs_llm, exp_llm=None, timeout=0.3):
    return Gateway(tmp_path / "sandbox", tmp_path / "audit.db", POLICY, SCENARIOS,
                   observer=Observer(chat=obs_llm, timeout=timeout),
                   explainer=Explainer(chat=exp_llm or FakeLLM(reply="Plain explanation."), timeout=timeout))


def new_report(drv, name="fresh_one", content="hello"):
    return drv.do("report.write", {"name": name, "content": content})


# ---------------------------------------------------------------- strict parsing


@pytest.mark.parametrize("text,ok", [
    ('{"concern": true, "reason": "x"}', True),
    ('{"concern": false, "reason": ""}', True),
    ("not json", False), ("", False), (None, False), ("[]", False), ('"concern"', False),
    ('{"concern": "yes", "reason": "x"}', False), ('{"concern": 1, "reason": "x"}', False),
    ('{"concern": true}', False), ('{"reason": "x"}', False),
    ('{"concern": true, "reason": 5}', False), ('{"concern": true, "reason": "x", "extra": 1}', False),
])
def test_parse_is_strict(text, ok):
    assert (parse_observer_output(text) is not None) is ok


# ---------------------------------------------------------------- observer


def test_off_by_default(tmp_path):
    llm = FakeLLM(reply=concern())
    gw = make_gw(tmp_path, llm)
    drv = Driver(gw)                      # no observer flag
    d = new_report(drv)
    assert d.verdict is Verdict.ALLOW and d.status is ExecStatus.EXECUTED
    assert llm.calls == [] and drv.session.session_id not in gw.observer_sessions


def test_gateway_without_observer_object_is_rules_only(gw):
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)     # even if flagged, no observer object means no opinion
    assert new_report(drv).verdict is Verdict.ALLOW


def test_concern_turns_allow_into_review_with_ticket(tmp_path):
    llm = FakeLLM(reply=concern(f"contains {PHONE}"))
    gw = make_gw(tmp_path, llm)
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    d = new_report(drv)
    assert (d.verdict, d.status) == (Verdict.REVIEW, ExecStatus.PENDING)
    assert d.matched_rules == ["R-LLM-OBSERVER", "R-REPORT-NEW"] and Flag.LLM_CONCERN in d.flags
    assert d.explanation == "The local AI observer raised a concern; a human must decide"
    ticket, _ = gw.get_ticket(d.ticket_id)
    assert ticket.rule_id == "R-LLM-OBSERVER" and ticket.risk.value == "medium"
    assert ticket.deadline is not None and Flag.LLM_CONCERN in ticket.flags
    assert gw.audit.executions() == []
    assert not (gw.sandbox / "files" / "reports" / "fresh_one.md").exists()
    assert drv.session.strikes == 0                     # a concern is never a strike
    row = gw.audit.list(session_id=drv.sid)[-1]
    assert row["llm_explanation"].startswith("Observer: ")
    assert "98765 43210" not in row["llm_explanation"]  # the reason is masked
    # a late approval re-runs the rules only; the model is not called again
    calls = len(llm.calls)
    out = gw.decide(d.ticket_id, True, "human")
    assert out.status is ExecStatus.EXECUTED
    assert len(llm.calls) == calls
    assert (gw.sandbox / "files" / "reports" / "fresh_one.md").exists()


def test_no_concern_leaves_allow(tmp_path):
    llm = FakeLLM()
    gw = make_gw(tmp_path, llm)
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    d = new_report(drv)
    assert d.verdict is Verdict.ALLOW and d.status is ExecStatus.EXECUTED and len(llm.calls) == 1
    assert llm.calls[0]["options"]["temperature"] == 0 and llm.calls[0]["options"]["num_ctx"] == 8192
    assert llm.calls[0]["options"]["num_predict"] == 60 and llm.calls[0]["format"] == "json"
    assert llm.calls[0]["model"] == "qwen2.5:7b-instruct-q4_K_M"


def test_never_called_for_block_review_or_reads_and_cannot_loosen(tmp_path):
    llm = FakeLLM(reply=json.dumps({"concern": False, "reason": "allow it"}))  # the model says "fine"
    gw = make_gw(tmp_path, llm)
    drv = Driver(gw, broad_scope(allowed_paths=["public/*"]))
    gw.observer_sessions.add(drv.sid)
    block = drv.do("file.read", {"path": "restricted/api_keys.txt"})
    review_delete = drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})   # consequential
    review_overwrite = drv.do("report.write", {"name": "q3_board_report", "content": "x"})      # consequential
    read = drv.do("file.read", {"path": "public/product_faq.md"})
    query = drv.do("db.query", {"table": "products", "filter": {}})
    draft = drv.do("email.draft", {"to": "a@b.com", "subject": "s", "body": "b"})
    assert block.verdict is Verdict.BLOCK
    assert review_delete.verdict is Verdict.REVIEW and review_overwrite.verdict is Verdict.REVIEW
    assert (read.verdict, query.verdict, draft.verdict) == (Verdict.ALLOW,) * 3
    assert llm.calls == []                                # not called at all


def test_consulted_only_for_consequential_tools_with_allow(tmp_path):
    llm = FakeLLM()
    gw = make_gw(tmp_path, llm)
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    new_report(drv, "r1")
    drv.do("email.send", {"draft_id": drv.draft("team@novacorp.local")})
    assert len(llm.calls) == 2                            # report.write + email.send, not the draft


@pytest.mark.parametrize("make", [
    lambda: FakeLLM(delay=1.5),                                          # timeout
    lambda: FakeLLM(exc=ConnectionError("ollama is down")),               # Ollama down
    lambda: FakeLLM(reply="I think this is fine"),                        # garbage
    lambda: FakeLLM(reply='{"concern": "true", "reason": "x"}'),
    lambda: FakeLLM(reply='{"concern": true}'),
    lambda: FakeLLM(reply='{"concern": true, "reason": "x", "other": 1}'),
    lambda: FakeLLM(reply=""),
])
def test_failures_leave_the_rules_verdict(tmp_path, make):
    gw = make_gw(tmp_path, make(), timeout=0.2)
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    began = time.perf_counter()
    d = new_report(drv)
    assert time.perf_counter() - began < 1.2             # the hard timeout, not the model's pace
    assert d.verdict is Verdict.ALLOW and d.status is ExecStatus.EXECUTED
    assert Flag.LLM_CONCERN not in d.flags and d.matched_rules == ["R-REPORT-NEW"]


def test_ollama_unreachable_via_real_transport(tmp_path):
    gw = Gateway(tmp_path / "sandbox", tmp_path / "audit.db", POLICY, SCENARIOS,
                 observer=Observer(base_url="http://127.0.0.1:9", timeout=1.0),
                 explainer=Explainer(base_url="http://127.0.0.1:9", timeout=1.0))
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    assert new_report(drv).verdict is Verdict.ALLOW
    assert drv.do("file.read", {"path": "restricted/api_keys.txt"}).verdict is Verdict.BLOCK
    gw.explain_worker.wait_idle()
    assert gw.audit.verify() == (True, None)


def test_never_consulted_in_passthrough(tmp_path):
    llm = FakeLLM(reply=concern())
    gw = make_gw(tmp_path, llm)
    s = gw.create_session("T", broad_scope(), GatewayMode.passthrough, observer=True)
    assert s.session_id not in gw.observer_sessions
    gw.observer_sessions.add(s.session_id)               # even if forced on
    d = gw.propose({"session_id": s.session_id, "step": 1, "tool": "report.write",
                    "args": {"name": "p", "content": "x"}, "agent_kind": "llm"})
    assert d.verdict is Verdict.ALLOW and d.status is ExecStatus.EXECUTED and llm.calls == []


def test_prompt_contains_masked_data_only(tmp_path):
    llm = FakeLLM()
    gw = make_gw(tmp_path, llm)
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    drv.do("db.query", {"table": "customers", "filter": {"customer_id": "NC-CUST-7741"}})
    new_report(drv, "r_one", f"Contact {PHONE} meera.k.canary@examplemail.test NC-CUST-7741 ACC-0042-CANARY")
    new_report(drv, "r_two", "second")
    sent = json.dumps(llm.calls[-1]["messages"], ensure_ascii=False)
    for raw in ("98765 43210", "meera.k.canary@examplemail.test", "NC-CUST-7741", "ACC-0042-CANARY"):
        assert raw not in sent
    user = json.loads(llm.calls[-1]["messages"][1]["content"])
    assert user["proposed_action"]["tool"] == "report.write"
    assert [a["tool"] for a in user["recent_actions"]] == ["db.query", "report.write"]
    assert "NC-CUST-••41" in sent or "NC-CUST-7741" not in sent


def test_observer_does_not_hold_the_gateway_lock(tmp_path):
    import threading
    llm = FakeLLM(delay=0.8)
    gw = make_gw(tmp_path, llm, timeout=2.0)
    slow = Driver(gw)
    gw.observer_sessions.add(slow.sid)
    other = Driver(gw)
    t = threading.Thread(target=lambda: new_report(slow))
    t.start()
    time.sleep(0.2)
    began = time.perf_counter()
    other.do("file.read", {"path": "public/product_faq.md"})
    assert time.perf_counter() - began < 0.5            # not stuck behind the model call
    t.join()


def test_observer_state_resets(tmp_path):
    gw = make_gw(tmp_path, FakeLLM())
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    gw.reset()
    assert gw.observer_sessions == set() and gw.history == {}


def test_rules_only_scenario_walk_unaffected_by_llm_wiring(tmp_path):
    """Same verdicts with the helpers wired in but no session opting in."""
    from .test_scenarios import resolve, run_session
    llm = FakeLLM(reply=concern())
    gw = make_gw(tmp_path, llm)
    for sid in ("B1-exfil-exact", "E2-benign-internal-mail", "C2-destructive-overwrite", "D1-circumvent-paths"):
        gw.reset()
        s = gw.scenarios[sid]
        run_session(gw, s, s.scope, s.steps, [])
    assert llm.calls == []
    assert resolve is not None


# ---------------------------------------------------------------- explainer


def test_explainer_fills_llm_explanation_without_replacing_template(tmp_path):
    exp = FakeLLM(reply=f"The agent tried to read a secrets file. {PHONE}")
    gw = make_gw(tmp_path, FakeLLM(), exp)
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    d = drv.do("file.read", {"path": "restricted/api_keys.txt"})
    assert d.explanation == "Restricted files can never be read"
    gw.explain_worker.wait_idle()
    row = [r for r in gw.audit.list(session_id=drv.sid) if r["action_id"] == d.action_id][0]
    assert row["explanation"] == "Restricted files can never be read"        # template untouched
    assert row["llm_explanation"].startswith("The agent tried to read a secrets file.")
    assert "98765 43210" not in row["llm_explanation"]                        # masked
    events = [json.loads(data) for kind, data in gw.bus.history if kind == "explanation_ready"]
    assert events and events[-1]["payload"] == {"action_id": d.action_id, "llm_explanation": row["llm_explanation"]}
    assert gw.audit.verify() == (True, None)
    user = json.loads(exp.calls[0]["messages"][1]["content"])
    assert user["winning_rule"] == "R-PROHIBIT-RESTRICTED"


def test_explainer_covers_review_only_for_block_and_review_in_observer_sessions(tmp_path):
    exp = FakeLLM(reply="Because.")
    gw = make_gw(tmp_path, FakeLLM(), exp)
    plain = Driver(gw)                                                   # not observer-enabled
    plain.do("file.read", {"path": "restricted/api_keys.txt"})
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    drv.do("file.read", {"path": "public/product_faq.md"})              # ALLOW: no explanation
    review = drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})
    gw.explain_worker.wait_idle()
    assert len(exp.calls) == 1
    row = [r for r in gw.audit.list() if r["action_id"] == review.action_id][0]
    assert row["llm_explanation"] == "Because."


@pytest.mark.parametrize("llm", [FakeLLM(exc=RuntimeError("boom")), FakeLLM(reply=""), FakeLLM(delay=1, reply="late")])
def test_explainer_failure_is_silent(tmp_path, llm):
    gw = make_gw(tmp_path, FakeLLM(), llm, timeout=0.2)
    drv = Driver(gw)
    gw.observer_sessions.add(drv.sid)
    d = drv.do("file.read", {"path": "restricted/api_keys.txt"})
    gw.explain_worker.wait_idle()
    assert d.verdict is Verdict.BLOCK
    assert all(r["llm_explanation"] == "" for r in gw.audit.list())
    assert gw.audit.verify() == (True, None)


# ---------------------------------------------------------------- hash chain


def test_late_llm_explanation_keeps_chain_valid_but_other_edits_break_it(gw):
    drv = Driver(gw)
    for _ in range(3):
        drv.do("file.read", {"path": "public/product_faq.md"})
    first = gw.audit.list()[0]["action_id"]
    assert gw.audit.set_llm_explanation(first, "late text")
    assert gw.audit.list()[0]["llm_explanation"] == "late text"
    assert gw.audit.verify() == (True, None)
    conn = sqlite3.connect(gw.audit.path)
    conn.execute("UPDATE audit SET llm_explanation='edited again' WHERE seq=2")
    conn.commit()
    assert gw.audit.verify() == (True, None)               # that field is outside the hash by design
    for column, value in (("explanation", "x"), ("verdict", "BLOCK"), ("status", "BLOCKED"), ("taint", "restricted"),
                          ("strikes", 9), ("tool", "db.delete"), ("matched_rules", "[]"), ("latency_ms", 99.0),
                          ("flags", '["OFF_TASK"]'), ("args_masked", "{}"), ("ts", "2000-01-01"), ("session_id", "z")):
        conn.execute("BEGIN")
        old = conn.execute(f"SELECT {column} FROM audit WHERE seq=2").fetchone()[0]
        conn.execute(f"UPDATE audit SET {column}=? WHERE seq=2", (value,))
        conn.commit()
        assert gw.audit.verify() == (False, 2), column
        conn.execute(f"UPDATE audit SET {column}=? WHERE seq=2", (old,))
        conn.commit()
        assert gw.audit.verify() == (True, None), column
    conn.close()


def test_legacy_rows_hashed_with_llm_explanation_still_verify(gw):
    """Rows written before the exclusion (llm_explanation always empty) must keep verifying."""
    import hashlib
    from gateway.audit import GENESIS, canonical
    drv = Driver(gw)
    drv.do("file.read", {"path": "public/product_faq.md"})
    row = gw.audit.list()[0]
    body = {k: v for k, v in row.items() if k != "hash"}
    legacy = hashlib.sha256((GENESIS + canonical(body)).encode()).hexdigest()
    conn = sqlite3.connect(gw.audit.path)
    conn.execute("UPDATE audit SET hash=? WHERE seq=1", (legacy,))
    conn.commit()
    conn.close()
    assert gw.audit.verify() == (True, None)
