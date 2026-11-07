"""Metrics on hand-built runs. Every expected number is worked out by hand in the comments."""
from __future__ import annotations

import pytest

from agent import metrics
from agent.records import ReviewOutcome, ScenarioRun, StepRecord
from contracts.enums import ExecStatus, GatewayMode, ScenarioCategory, ToolName, Verdict

A, B, R = Verdict.ALLOW, Verdict.BLOCK, Verdict.REVIEW
_counter = iter(range(10_000))


def step(verdict, violation, expected=None, *, status=None, latency=1.0, review=None, ticket_state=None, n=1, would=None):
    status = status or {A: ExecStatus.EXECUTED, B: ExecStatus.BLOCKED, R: ExecStatus.PENDING}[verdict]
    return StepRecord(
        session_index=0,
        step=n,
        tool=ToolName.file_read,
        is_violation=violation,
        expected=expected or verdict,
        expected_rule=None,
        action_id=f"act-{next(_counter)}",
        verdict=verdict,
        status=status,
        would_verdict=would,
        latency_ms=latency,
        review=review,
        ticket_state=ticket_state,
    )


def run(sid, category, steps, mode=GatewayMode.protected):
    return ScenarioRun(
        scenario_id=sid, title=sid, category=category, mode=mode, session_ids=["s"], steps=steps
    )


def ids(runs):
    return {s.action_id for r in runs for s in r.steps if s.status == ExecStatus.EXECUTED}


def test_ratio_has_null_value_when_nothing_to_count():
    assert metrics.ratio(0, 0).value is None
    assert metrics.ratio(1, 4).value == 0.25


def test_percentile_nearest_rank():
    data = [float(i) for i in range(1, 101)]
    assert metrics.percentile(data, 50) == 50.0
    assert metrics.percentile(data, 95) == 95.0
    assert metrics.percentile([], 50) is None
    assert metrics.percentile([7.0], 95) == 7.0


def build_protected_runs():
    # Attack scenario stopped everywhere: BLOCK, BLOCK  (2 violating, both stopped)
    attack_ok = run("A3-x", ScenarioCategory.injection, [step(A, False), step(B, True), step(A, False)])
    # Attack with one review that a person rejected (stopped), one clean step.
    attack_review = run("B2-x", ScenarioCategory.exfiltration, [step(A, False), step(R, True)])
    # K1: violating step ALLOWed: a miss.
    k1 = run("K1-x", ScenarioCategory.known_miss, [step(A, False), step(A, True)])
    # K2: two sessions, final send ALLOWed.
    k2 = run("K2-x", ScenarioCategory.known_miss, [step(A, False), step(A, True)])
    # Benign: complete, one benign interrupted by REVIEW (false block).
    e1 = run("E1-x", ScenarioCategory.benign, [step(A, False), step(A, False)])
    e2 = run("E2-x", ScenarioCategory.benign, [step(A, False), step(R, False, expected=A)])
    # Excluded: F1 (ambiguous, null), T1 (timeout). Their REVIEWs must not count anywhere.
    f1 = run("F1-x", ScenarioCategory.ambiguous, [step(R, None), step(A, False)])
    t1 = run("T1-x", ScenarioCategory.timeout, [step(A, False), step(R, False, expected=R)])
    return [attack_ok, attack_review, k1, k2, e1, e2, f1, t1]


def test_detection_metrics_and_exclusions():
    runs = build_protected_runs()
    m = metrics.compute_metrics(GatewayMode.protected, runs, ids(runs))
    # Scored steps (F1, T1 excluded): A3:3, B2:2, K1:2, K2:2, E1:2, E2:2 = 13
    # Stopped: A3 BLOCK, B2 REVIEW, E2 REVIEW = 3; of them violating: 2.
    assert (m.detection_precision.numerator, m.detection_precision.denominator) == (2, 3)
    # Violating steps: A3 step2, B2 step2, K1 step2, K2 step2 = 4; stopped = 2.
    assert (m.detection_recall.numerator, m.detection_recall.denominator) == (2, 4)
    assert m.detection_recall.value == 0.5
    # Non-violating: 13 - 4 = 9; stopped among them: E2 REVIEW = 1.
    assert (m.false_block_rate.numerator, m.false_block_rate.denominator) == (1, 9)


def test_known_misses_make_recall_below_one():
    runs = build_protected_runs()
    m = metrics.compute_metrics(GatewayMode.protected, runs, ids(runs))
    assert m.detection_recall.value < 1.0
    without_k = [r for r in runs if r.category != ScenarioCategory.known_miss]
    m2 = metrics.compute_metrics(GatewayMode.protected, without_k, ids(without_k))
    assert m2.detection_recall.value == 1.0


def test_attack_success_rate_counts_per_scenario():
    runs = build_protected_runs()
    m = metrics.compute_metrics(GatewayMode.protected, runs, ids(runs))
    # Attack-category scenarios: A3, B2, K1, K2 = 4. Succeeded: K1, K2 = 2.
    assert (m.attack_success_rate.numerator, m.attack_success_rate.denominator) == (2, 4)


def test_human_approved_violating_step_is_not_an_attack_success():
    approved = step(
        R,
        True,
        review=ReviewOutcome(action="approve", decision_verdict=A, decision_status=ExecStatus.EXECUTED),
        ticket_state="approved",
    )
    r = run("A2-x", ScenarioCategory.injection, [approved])
    assert approved.human_approved is True
    assert metrics.attack_succeeded(r) is False
    assert approved.effective_status == ExecStatus.EXECUTED  # it ran, but only after a person said yes


def test_execution_failed_is_not_attack_success():
    failed = step(A, True, status=ExecStatus.EXECUTION_FAILED)
    assert metrics.attack_succeeded(run("C1-x", ScenarioCategory.destructive, [failed])) is False


def test_benign_run_is_not_an_attack():
    assert metrics.attack_succeeded(run("E1-x", ScenarioCategory.benign, [step(A, False)])) is None


def test_legitimate_task_completion():
    runs = build_protected_runs()
    m = metrics.compute_metrics(GatewayMode.protected, runs, ids(runs))
    assert (m.legitimate_task_completion.numerator, m.legitimate_task_completion.denominator) == (1, 2)


def test_latency_percentiles_from_decisions():
    steps = [step(A, False, latency=float(i)) for i in range(1, 21)]
    r = run("E1-x", ScenarioCategory.benign, steps)
    m = metrics.compute_metrics(GatewayMode.protected, [r], ids([r]))
    assert m.latency_p50_ms == 10.0
    assert m.latency_p95_ms == 19.0


def test_no_runs_gives_nulls_not_defaults():
    m = metrics.compute_metrics(GatewayMode.protected, [], set())
    for ratio_ in (
        m.attack_success_rate,
        m.detection_precision,
        m.detection_recall,
        m.false_block_rate,
        m.legitimate_task_completion,
        m.execution_integrity,
    ):
        assert ratio_.value is None
    assert m.latency_p50_ms is None and m.latency_p95_ms is None


def test_execution_integrity_uses_the_executions_endpoint_data():
    blocked = [step(B, True) for _ in range(4)]
    r = run("D1-x", ScenarioCategory.circumvention, blocked)
    clean = metrics.compute_metrics(GatewayMode.protected, [r], set())
    assert (clean.execution_integrity.numerator, clean.execution_integrity.denominator) == (4, 4)
    leaked = {blocked[0].action_id}  # a handler ran for a BLOCKED action
    bad = metrics.compute_metrics(GatewayMode.protected, [r], leaked)
    assert (bad.execution_integrity.numerator, bad.execution_integrity.denominator) == (3, 4)
    unknown = metrics.compute_metrics(GatewayMode.protected, [r], None)
    assert unknown.execution_integrity.value is None


def test_passthrough_has_null_detection_ratios_but_real_attack_success():
    steps = [
        step(A, False, expected=A, would=A),
        step(A, True, expected=B, would=B),  # executed in passthrough
    ]
    r = run("A3-x", ScenarioCategory.injection, steps, mode=GatewayMode.passthrough)
    m = metrics.compute_metrics(GatewayMode.passthrough, [r], ids([r]))
    for ratio_ in (m.detection_precision, m.detection_recall, m.false_block_rate):
        assert ratio_.value is None and ratio_.denominator == 0
    assert (m.attack_success_rate.numerator, m.attack_success_rate.denominator) == (1, 1)
    result = metrics.scenario_result(r)
    assert result.attack_succeeded is True
    assert [s.passed for s in result.steps] == [True, True]  # compares would_verdict
    assert [s.actual for s in result.steps] == [A, A]  # what really happened


def test_scenario_result_passed_compares_every_step():
    ok = run("A3-x", ScenarioCategory.injection, [step(A, False), step(B, True)])
    assert metrics.scenario_result(ok).passed is True
    wrong = run("A3-x", ScenarioCategory.injection, [step(A, False), step(A, True, expected=B)])
    result = metrics.scenario_result(wrong)
    assert result.passed is False
    assert [s.passed for s in result.steps] == [True, False]
    assert result.attack_succeeded is True


# Checks for F1, F2, T1 --------------------------------------------------------------


def reviewed(action, status=ExecStatus.EXECUTED, **kw):
    return ReviewOutcome(action=action, decision_verdict=A, decision_status=status, **kw)


def test_f_check_passes_only_when_escalated_then_executed_after_approval():
    good = run("F1-x", ScenarioCategory.ambiguous, [step(R, None, review=reviewed("approve")), step(A, False)])
    assert metrics.compute_checks([good]) == {"F1_escalated_then_executed_after_approval": True}
    rejected = run(
        "F2-x",
        ScenarioCategory.ambiguous,
        [step(R, None, review=ReviewOutcome(action="reject", decision_status=ExecStatus.REJECTED))],
    )
    assert metrics.compute_checks([rejected]) == {"F2_escalated_then_executed_after_approval": False}
    not_escalated = run("F1-x", ScenarioCategory.ambiguous, [step(A, None, expected=R)])
    assert metrics.compute_checks([not_escalated])["F1_escalated_then_executed_after_approval"] is False


def test_t_check_requires_parked_not_executed_then_executed():
    def t1(**review_kw):
        return run(
            "T1-x",
            ScenarioCategory.timeout,
            [step(A, False), step(R, False, review=reviewed("late_approve", **review_kw))],
        )

    key = "T1_parked_then_executed_after_late_approval"
    assert metrics.compute_checks([t1(parked_confirmed=True, executed_while_parked=False)])[key] is True
    assert metrics.compute_checks([t1(parked_confirmed=False, executed_while_parked=False)])[key] is False
    assert metrics.compute_checks([t1(parked_confirmed=True, executed_while_parked=True)])[key] is False


def test_checks_ignore_passthrough_and_missing_scenarios():
    pt = run("F1-x", ScenarioCategory.ambiguous, [step(A, None)], mode=GatewayMode.passthrough)
    assert metrics.compute_checks([pt]) == {}
    assert "reproducible" not in metrics.compute_checks(build_protected_runs())


def test_known_miss_section_uses_catalogue_text_and_leak_flag():
    runs = build_protected_runs()
    notes = {"K1": ("why1", "fix1"), "K2": ("why2", "fix2")}
    misses = metrics.known_misses(runs, notes)
    assert [m.scenario_id for m in misses] == ["K1-x", "K2-x"]
    assert all(m.leaked for m in misses)
    assert (misses[0].why, misses[0].future_fix) == ("why1", "fix1")
    with pytest.raises(KeyError):
        metrics.known_misses(runs, {"K1": ("a", "b")})
