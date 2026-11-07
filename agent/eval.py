"""Evaluation runner: every scenario, protected and passthrough, into one EvalReport.

    python -m agent.eval --report-id ID --gateway URL [--stub] [--verify-reproducible]

Writes reports_out/<id>.json atomically (status running first, then complete or failed).
Every number comes from a real run against whatever gateway answers at --gateway.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx

from agent import admin, metrics
from agent.llm_agent import DEFAULT_MODEL, FALLBACK_MODEL, OLLAMA_URL
from agent.records import ScenarioRun
from agent.reviewer import ScriptedReviewer
from agent.runner import DEFAULT_REVIEW_TIMEOUT_S, run_scenario
from agent.scenarios import (
    SCENARIO_DIR,
    load_all,
    load_canaries,
    load_known_miss_notes,
)
from contracts.enums import GatewayMode
from contracts.models import EvalReport

DEFAULT_OUT_DIR = Path(__file__).resolve().parents[1] / "reports_out"
DEFAULT_GATEWAY = "http://127.0.0.1:8000"
STUB_URL = "http://127.0.0.1:8001"
STUB_LABEL = "STUB GATEWAY, not a real score"
LLM_LABEL = "rules + LLM observer, may vary slightly"
MODES = (GatewayMode.protected, GatewayMode.passthrough)


def write_report(report: EvalReport, out_dir: Path) -> Path:
    """Atomic write: temp file in the same folder, then rename over the target."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{report.report_id}.json"
    fd, tmp_name = tempfile.mkstemp(dir=out_dir, prefix=f".{report.report_id}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(report.model_dump_json(indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


def run_all(
    gateway: str,
    *,
    scenarios_dir: Path | None = None,
    poll_interval: float = 1.0,
    review_timeout: float = DEFAULT_REVIEW_TIMEOUT_S,
    only: list[str] | None = None,
    log=None,
    observer: bool = False,
) -> tuple[list[ScenarioRun], dict[GatewayMode, set[str]]]:
    """Run each scenario in both modes; reset the sandbox before each run."""
    say = log or (lambda _m: None)
    scenarios = load_all(scenarios_dir)
    if only:
        wanted = {w.lower() for w in only}
        scenarios = [s for s in scenarios if s.id.lower() in wanted or s.id.split("-")[0].lower() in wanted]
    canaries = load_canaries(scenarios_dir or SCENARIO_DIR)
    runs: list[ScenarioRun] = []
    executed: dict[GatewayMode, set[str]] = {m: set() for m in MODES}
    with httpx.Client(base_url=gateway.rstrip("/"), timeout=30.0) as ops:
        for scenario in scenarios:
            for mode in MODES:
                say(f"{scenario.id} [{mode.value}]")
                admin.reset_sandbox(ops)
                reviewer = ScriptedReviewer(gateway)
                run = run_scenario(
                    scenario,
                    mode,
                    gateway,
                    canaries=canaries,
                    reviewer=reviewer,
                    poll_interval=poll_interval,
                    review_timeout=review_timeout,
                    log=say,
                    # The observer only exists in protected mode; passthrough never enforces.
                    observer=observer and mode == GatewayMode.protected,
                )
                runs.append(run)
                # Fetched after every run, in case a reset clears the execution log.
                executed[mode] |= admin.fetch_execution_ids(ops)
    return runs, executed


def build_report(
    report_id: str,
    runs: list[ScenarioRun],
    executed: dict[GatewayMode, set[str]],
    notes: dict[str, tuple[str, str]],
    *,
    label: str = "",
    with_llm: bool = False,
) -> EvalReport:
    return EvalReport(
        report_id=report_id,
        status="complete",
        generated_at=datetime.now(timezone.utc),
        with_llm=with_llm,
        metrics=[metrics.compute_metrics(m, runs, executed[m]) for m in MODES],
        scenarios=[metrics.scenario_result(r, label) for r in runs],
        known_misses=metrics.known_misses(runs, notes),
        checks=metrics.compute_checks(runs),
    )


def comparable(report: EvalReport) -> dict:
    """Report content with latency removed, for the reproducibility comparison."""
    data = report.model_dump(mode="json", exclude={"generated_at", "report_id"})
    for m in data["metrics"]:
        m.pop("latency_p50_ms", None)
        m.pop("latency_p95_ms", None)
    for s in data["scenarios"]:
        for step in s["steps"]:
            step.pop("latency_ms", None)
    data["checks"].pop("reproducible", None)
    return data


def ensure_llm_available(gateway: str, ollama_url: str = OLLAMA_URL) -> None:
    """Refuse to produce a 'rules + LLM' report unless Ollama is really there. Never fakes a column."""
    try:
        tags = httpx.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=5.0)
        tags.raise_for_status()
        names = {m.get("name") for m in tags.json().get("models", [])}
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        raise RuntimeError(f"Ollama is not available at {ollama_url} ({type(exc).__name__}); "
                           "the rules + LLM column was not produced") from exc
    if DEFAULT_MODEL not in names and FALLBACK_MODEL not in names:
        raise RuntimeError(f"Ollama has neither {DEFAULT_MODEL} nor {FALLBACK_MODEL}; the rules + LLM column was not produced")
    try:
        health = httpx.get(f"{gateway.rstrip('/')}/health", timeout=5.0).json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(f"gateway /health unreadable ({type(exc).__name__})") from exc
    if isinstance(health, dict) and health.get("ollama_available") is False:
        raise RuntimeError("the gateway reports Ollama as unavailable; the rules + LLM column was not produced")


def run_eval(
    report_id: str,
    gateway: str,
    out_dir: Path,
    *,
    label: str = "",
    scenarios_dir: Path | None = None,
    poll_interval: float = 1.0,
    verify_reproducible: bool = False,
    only: list[str] | None = None,
    log=None,
    with_llm: bool = False,
    ollama_url: str = OLLAMA_URL,
) -> EvalReport:
    write_report(EvalReport(report_id=report_id, status="running", with_llm=with_llm), out_dir)
    if with_llm:
        label = "; ".join(x for x in (label, LLM_LABEL) if x)
    try:
        if with_llm:
            ensure_llm_available(gateway, ollama_url)
        notes = load_known_miss_notes()
        runs, executed = run_all(
            gateway, scenarios_dir=scenarios_dir, poll_interval=poll_interval, only=only, log=log,
            observer=with_llm,
        )
        report = build_report(report_id, runs, executed, notes, label=label, with_llm=with_llm)
        if verify_reproducible:
            runs2, executed2 = run_all(
                gateway, scenarios_dir=scenarios_dir, poll_interval=poll_interval, only=only, log=log,
                observer=with_llm,
            )
            second = build_report(report_id, runs2, executed2, notes, label=label, with_llm=with_llm)
            report.checks["reproducible"] = comparable(report) == comparable(second)
    except Exception as exc:  # any break must become a failed report, never a half-written one
        failed = EvalReport(
            report_id=report_id,
            status="failed",
            generated_at=datetime.now(timezone.utc),
            with_llm=with_llm,
            error=f"{type(exc).__name__}: {exc}",
        )
        write_report(failed, out_dir)
        return failed
    write_report(report, out_dir)
    return report


def _fmt(r) -> str:
    return "n/a" if r.value is None else f"{r.value * 100:.1f}% ({r.numerator}/{r.denominator})"


def print_summary(report: EvalReport, stub: bool) -> None:
    if stub:
        print(f"*** {STUB_LABEL} ***")
    print(f"report {report.report_id}: {report.status}")
    if report.error:
        print(f"error: {report.error}")
        return
    for m in report.metrics:
        print(f"[{m.mode.value}]")
        print(f"  attack success rate : {_fmt(m.attack_success_rate)}")
        print(f"  detection precision : {_fmt(m.detection_precision)}")
        print(f"  detection recall    : {_fmt(m.detection_recall)}")
        print(f"  false-block rate    : {_fmt(m.false_block_rate)}")
        print(f"  task completion     : {_fmt(m.legitimate_task_completion)}")
        p50 = "n/a" if m.latency_p50_ms is None else f"{m.latency_p50_ms:.2f}"
        p95 = "n/a" if m.latency_p95_ms is None else f"{m.latency_p95_ms:.2f}"
        print(f"  latency p50/p95 ms  : {p50} / {p95}")
        print(f"  execution integrity : {_fmt(m.execution_integrity)}")
    print(f"checks: {report.checks}")
    print("known misses: " + ", ".join(f"{k.scenario_id} leaked={k.leaked}" for k in report.known_misses))
    failed = [s for s in report.scenarios if s.mode == GatewayMode.protected and not s.passed]
    print(f"protected scenarios not matching expected: {[s.scenario_id for s in failed] or 'none'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent.eval", description=__doc__)
    parser.add_argument("--report-id", required=True)
    parser.add_argument("--gateway", default=None, help=f"default {DEFAULT_GATEWAY}, or the stub with --stub")
    parser.add_argument("--stub", action="store_true", help="start the bundled stub gateway on port 8001 and use it")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--only", help="comma-separated scenario ids or short ids (for a quick trial)")
    parser.add_argument("--with-llm", action="store_true", help="enable the gateway's LLM observer (needs Ollama); report has with_llm true")
    parser.add_argument("--ollama-url", default=OLLAMA_URL)
    parser.add_argument("--verify-reproducible", action="store_true", help="run everything twice and set the reproducible check")
    args = parser.parse_args(argv)

    handle = None
    gateway = args.gateway or (STUB_URL if args.stub else DEFAULT_GATEWAY)
    if args.stub:
        from agent.stub_gateway import start_in_thread

        handle = start_in_thread(port=8001)
        gateway = args.gateway or STUB_URL
    try:
        report = run_eval(
            args.report_id,
            gateway,
            args.out_dir,
            label=STUB_LABEL if args.stub else "",
            poll_interval=args.poll_interval,
            verify_reproducible=args.verify_reproducible,
            with_llm=args.with_llm,
            ollama_url=args.ollama_url,
            only=args.only.split(",") if args.only else None,
            log=lambda m: print(m, flush=True),
        )
    finally:
        if handle is not None:
            handle.stop()
    print_summary(report, args.stub)
    print(f"written: {args.out_dir / (args.report_id + '.json')}")
    return 0 if report.status == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
