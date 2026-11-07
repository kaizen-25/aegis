"""End-to-end tests of the runner, reviewer, CLI and eval against the stub gateway on port 8001.

The stub takes its verdicts from each scenario's `expected`, so these tests prove the agent
plumbing and the metric arithmetic. They say nothing about how the real gateway behaves.
"""
from __future__ import annotations

import json
import os

import httpx
import pytest

from agent import admin, eval as agent_eval, metrics, run as agent_run
from agent.reviewer import ScriptedReviewer
from agent.runner import RunnerError, run_scenario
from agent.scenarios import find_scenario, load_all, load_canaries
from agent.stub_gateway import start_in_thread
from contracts.enums import ExecStatus, GatewayMode, Verdict
from contracts.models import EvalReport

URL = "http://127.0.0.1:8001"
FAST = 0.05


@pytest.fixture(scope="module", autouse=True)
def stub():
    try:
        httpx.get(f"{URL}/health", timeout=1)
    except httpx.HTTPError:
        pass
    else:
        pytest.fail("port 8001 is already in use; stop whatever is running there")
    handle = start_in_thread(port=8001)
    yield handle
    handle.stop()


@pytest.fixture(scope="module")
def scenarios():
    return load_all()


@pytest.fixture(scope="module")
def canaries():
    return load_canaries()


def run_one(scenarios, canaries, short, mode=GatewayMode.protected, **kwargs):
    scenario = find_scenario(short, scenarios)
    reviewer = kwargs.pop("reviewer", ScriptedReviewer(URL))
    return run_scenario(scenario, mode, URL, canaries=canaries, reviewer=reviewer, poll_interval=FAST, **kwargs)


def test_a1_reject_does_not_stop_later_steps(scenarios, canaries):
    run = run_one(scenarios, canaries, "A1")
    assert [s.verdict for s in run.steps] == [Verdict.ALLOW, Verdict.REVIEW, Verdict.ALLOW]
    review_step = run.steps[1]
    assert review_step.review.action == "reject"
    assert review_step.ticket_state == "rejected"
    assert review_step.effective_status == ExecStatus.REJECTED
    assert run.steps[2].status == ExecStatus.EXECUTED  # step 3 ran after the rejection
    assert metrics.scenario_result(run).passed is True


def test_d1_attempts_all_four_steps(scenarios, canaries):
    run = run_one(scenarios, canaries, "D1")
    assert [s.step for s in run.steps] == [1, 2, 3, 4]
    assert all(s.verdict == Verdict.BLOCK for s in run.steps)


def test_b1_resolves_placeholders_into_the_request(scenarios, canaries):
    sent = []
    http = httpx.Client(
        base_url=URL,
        event_hooks={"request": [lambda r: sent.append((r.url.path, r.content))]},
    )
    run_one(scenarios, canaries, "B1", http_client=http)
    bodies = [json.loads(c) for p, c in sent if p == "/actions/propose"]
    assert canaries["phone_1"] in bodies[1]["args"]["body"]
    assert bodies[2]["args"]["draft_id"].startswith("draft-")  # {{last_draft}} came from step 2
    assert all("{{" not in c.decode() for _, c in sent)


def test_agent_only_calls_the_three_allowed_endpoints(scenarios, canaries):
    paths = []
    http = httpx.Client(
        base_url=URL,
        event_hooks={"request": [lambda r: paths.append((r.method, r.url.path))]},
    )
    run_one(scenarios, canaries, "A1", http_client=http)
    for method, path in paths:
        assert (method, path) in {("POST", "/sessions"), ("POST", "/actions/propose")} or (
            method == "GET" and path.startswith("/tickets/") and path.count("/") == 2
        ), (method, path)
    assert ("GET", "/audit/executions") not in paths


def test_k2_runs_two_sessions(scenarios, canaries):
    run = run_one(scenarios, canaries, "K2")
    assert len(run.session_ids) == 2 and run.session_ids[0] != run.session_ids[1]
    assert [(s.session_index, s.step) for s in run.steps] == [(0, 1), (0, 2), (1, 1), (1, 2), (1, 3)]
    assert metrics.attack_succeeded(run) is True


def test_existing_session_ids_are_used(scenarios, canaries):
    scenario = find_scenario("K2", scenarios)
    ids = []
    with httpx.Client(base_url=URL) as client:
        from agent.scenarios import scenario_sessions

        for scope, _ in scenario_sessions(scenario):
            r = client.post("/sessions", json={"scenario_id": scenario.id, "scope": scope.model_dump(mode="json"), "mode": "protected"})
            ids.append(r.json()["session_id"])
    run = run_one(scenarios, canaries, "K2", session_ids=ids)
    assert run.session_ids == ids
    with pytest.raises(RunnerError, match="session"):
        run_one(scenarios, canaries, "K2", session_ids=ids[:1])


def test_unknown_session_is_recorded_as_fail_closed(scenarios, canaries):
    run = run_one(scenarios, canaries, "E1", session_ids=["no-such-session"])
    assert all(s.verdict == Verdict.BLOCK and s.status == ExecStatus.FAIL_CLOSED for s in run.steps)


def test_t1_late_approval_flow(scenarios, canaries):
    run = run_one(scenarios, canaries, "T1")
    step = run.steps[1]
    assert step.verdict == Verdict.REVIEW
    assert step.review.action == "late_approve"
    assert step.review.parked_confirmed is True
    assert step.review.executed_while_parked is False
    assert step.review.decision_status == ExecStatus.EXECUTED
    assert metrics.compute_checks([run]) == {"T1_parked_then_executed_after_late_approval": True}


@pytest.mark.parametrize("short", ["F1", "F2"])
def test_f_scenarios_escalate_then_execute(scenarios, canaries, short):
    run = run_one(scenarios, canaries, short)
    assert run.steps[0].verdict == Verdict.REVIEW
    assert run.steps[0].review.action == "approve"
    assert run.steps[1].status == ExecStatus.EXECUTED
    assert list(metrics.compute_checks([run]).values()) == [True]
    assert metrics.attack_succeeded(run) is None


def test_no_reviewer_waits_until_timeout_then_continues(scenarios, canaries):
    scenario = find_scenario("A1", scenarios)
    run = run_scenario(
        scenario, GatewayMode.protected, URL, canaries=canaries, reviewer=None, poll_interval=FAST, review_timeout=0.3
    )
    assert run.steps[1].ticket_state == "pending"  # nobody decided; never auto-approved
    assert run.steps[1].effective_status == ExecStatus.PENDING
    assert len(run.steps) == 3


def test_passthrough_executes_everything_and_reports_would_verdict(scenarios, canaries):
    run = run_one(scenarios, canaries, "B1", mode=GatewayMode.passthrough)
    assert all(s.status == ExecStatus.EXECUTED for s in run.steps)
    assert run.steps[2].would_verdict == Verdict.BLOCK
    assert metrics.attack_succeeded(run) is True


def test_cli_runs_a_scenario(capsys):
    assert agent_run.main(["B1", "--mode", "protected", "--gateway", URL, "--poll-interval", "0.05"]) == 0
    out = capsys.readouterr().out
    assert "B1-exfil-exact" in out and "BLOCK" in out and "attack_succeeded=False" in out


def test_cli_unknown_scenario(capsys):
    assert agent_run.main(["Z9", "--gateway", URL]) == 2


# Eval ---------------------------------------------------------------------------------


def test_write_report_is_atomic(tmp_path, monkeypatch):
    report = EvalReport(report_id="r1", status="running")
    agent_eval.write_report(report, tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["r1.json"]
    before = (tmp_path / "r1.json").read_text()

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        agent_eval.write_report(EvalReport(report_id="r1", status="complete"), tmp_path)
    assert (tmp_path / "r1.json").read_text() == before  # old file untouched
    assert [p.name for p in tmp_path.iterdir()] == ["r1.json"]  # temp file cleaned up


def test_eval_failure_writes_failed_report(tmp_path, monkeypatch):
    def broken(_client):
        raise admin.AdminError("gateway unreachable")

    monkeypatch.setattr(admin, "reset_sandbox", broken)
    report = agent_eval.run_eval("fail1", URL, tmp_path, poll_interval=FAST, only=["E1"])
    assert report.status == "failed"
    on_disk = EvalReport.model_validate_json((tmp_path / "fail1.json").read_text())
    assert on_disk.status == "failed" and "gateway unreachable" in on_disk.error


def test_full_eval_against_stub_and_reproducible(tmp_path):
    report = agent_eval.run_eval(
        "stub-full",
        URL,
        tmp_path,
        label=agent_eval.STUB_LABEL,
        poll_interval=FAST,
        verify_reproducible=True,
    )
    assert report.status == "complete"
    on_disk = EvalReport.model_validate_json((tmp_path / "stub-full.json").read_text())
    assert on_disk.status == "complete"
    assert len(on_disk.scenarios) == 40  # 20 scenarios x 2 modes
    assert [p.name for p in tmp_path.iterdir()] == ["stub-full.json"]

    protected, passthrough = on_disk.metrics
    assert protected.mode == GatewayMode.protected and passthrough.mode == GatewayMode.passthrough
    # Attack denominator is 12 in both modes.
    assert protected.attack_success_rate.denominator == 12
    assert passthrough.attack_success_rate.denominator == 12
    # With the stub, only K1 and K2 get through when protected; everything succeeds unprotected.
    assert protected.attack_success_rate.numerator == 2
    assert passthrough.attack_success_rate.numerator == 12
    assert protected.detection_recall.value < 1.0
    assert passthrough.detection_precision.value is None
    assert protected.legitimate_task_completion.denominator == 5
    assert protected.execution_integrity.denominator > 0
    assert protected.execution_integrity.value == 1.0
    assert {m.scenario_id[:2] for m in on_disk.known_misses} == {"K1", "K2"}
    assert all(m.why and m.future_fix for m in on_disk.known_misses)
    assert on_disk.checks["F1_escalated_then_executed_after_approval"] is True
    assert on_disk.checks["F2_escalated_then_executed_after_approval"] is True
    assert on_disk.checks["T1_parked_then_executed_after_late_approval"] is True
    # The "reproducible" check came from really running everything twice and comparing.
    assert on_disk.checks["reproducible"] is True
    assert all(agent_eval.STUB_LABEL in s.detail for s in on_disk.scenarios)


def test_reproducible_check_absent_unless_verified(tmp_path):
    report = agent_eval.run_eval("one", URL, tmp_path, poll_interval=FAST, only=["E1"])
    assert "reproducible" not in report.checks


def test_comparable_detects_a_difference(tmp_path):
    a = agent_eval.run_eval("c1", URL, tmp_path, poll_interval=FAST, only=["E1", "B1"])
    b = a.model_copy(deep=True)
    assert agent_eval.comparable(a) == agent_eval.comparable(b)
    b.scenarios[0].passed = not b.scenarios[0].passed
    assert agent_eval.comparable(a) != agent_eval.comparable(b)
    # latency alone must not matter
    c = a.model_copy(deep=True)
    c.scenarios[0].steps[0].latency_ms += 123.0
    c.metrics[0].latency_p50_ms = 999.0
    assert agent_eval.comparable(a) == agent_eval.comparable(c)
