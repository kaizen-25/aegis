"""Run one scenario through the gateway.

    python -m agent.run B1 --mode protected --gateway http://127.0.0.1:8000
    python -m agent.run K2 --session-ids sess-a,sess-b --reviewer human
    python -m agent.run A1 --agent-kind llm --step-delay 2     (live model via Ollama)
"""
from __future__ import annotations

import argparse
import sys

import httpx

from agent import admin
from agent.metrics import scenario_result
from agent.llm_agent import DEFAULT_MODEL, FALLBACK_MODEL, OLLAMA_URL, LlmError, OllamaClient, run_llm_agent
from agent.reviewer import ScriptedReviewer
from agent.runner import HUMAN_REVIEW_TIMEOUT_S, RunnerError, run_scenario
from agent.scenarios import ScenarioError, find_scenario, load_all, load_canaries
from contracts.enums import AgentKind, GatewayMode

DEFAULT_GATEWAY = "http://127.0.0.1:8000"


def _run_llm(args, scenario, canaries, session_ids, mode, reviewer, timeout) -> int:
    chat = OllamaClient(model=args.model, base_url=args.ollama_url)
    try:
        chat.check_available()
        if args.reset:
            with httpx.Client(base_url=args.gateway.rstrip("/"), timeout=30.0) as ops:
                admin.reset_sandbox(ops)
        print(f"model={chat.model} (live run; results can vary)")
        run = run_llm_agent(
            scenario,
            mode,
            args.gateway,
            chat=chat,
            canaries=canaries,
            session_ids=session_ids,
            reviewer=reviewer,
            poll_interval=args.poll_interval,
            review_timeout=timeout,
            step_delay=args.step_delay,
            log=print,
        )
    except (LlmError, RunnerError, admin.AdminError, httpx.HTTPError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        chat.close()
    print(f"session: {run.session_id}")
    for s in run.steps:
        print(
            f"  step {s.step} {s.function:13} {s.verdict.value:6} {s.status:10} flags={s.flags} "
            f"gateway={s.gateway_latency_ms:.1f}ms model={s.model_ms:.0f}ms step={s.step_ms:.0f}ms"
        )
    print(f"stopped: {run.stopped}" + (f" | model said: {run.final_message[:200]}" if run.final_message else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent.run", description=__doc__)
    parser.add_argument("scenario_id", help="full id (B1-exfil-exact) or short prefix (B1)")
    parser.add_argument("--mode", choices=[m.value for m in GatewayMode], default="protected")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY)
    parser.add_argument("--session-ids", default=None, help="comma-separated existing sessions (K2 needs two)")
    parser.add_argument("--agent-kind", choices=[k.value for k in AgentKind], default="scripted")
    parser.add_argument("--reviewer", choices=["human", "scripted"], default=None, help="default: scripted for the scripted agent, human for the llm agent")
    parser.add_argument("--human-timeout", type=float, default=HUMAN_REVIEW_TIMEOUT_S, help="seconds to wait for a person")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--step-delay", type=float, default=0.0, help="seconds to pause after each step (demo pacing)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model for --agent-kind llm; speed fallback {FALLBACK_MODEL}")
    parser.add_argument("--ollama-url", default=OLLAMA_URL)
    parser.add_argument("--reset", action="store_true", help="POST /sandbox/reset before the run")
    args = parser.parse_args(argv)

    use_llm = args.agent_kind == AgentKind.llm.value
    if args.reviewer is None:
        args.reviewer = "human" if use_llm else "scripted"

    try:
        scenario = find_scenario(args.scenario_id, load_all())
        canaries = load_canaries()
    except ScenarioError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    session_ids = [s.strip() for s in args.session_ids.split(",") if s.strip()] if args.session_ids else None
    mode = GatewayMode(args.mode)
    human = args.reviewer == "human"
    reviewer = None if human else ScriptedReviewer(args.gateway)
    timeout = args.human_timeout if human else 60.0

    print(f"{scenario.id} [{mode.value}] reviewer={args.reviewer} gateway={args.gateway}")
    if human:
        print("Review steps wait for a person; decide them in the dashboard.")
    if use_llm:
        return _run_llm(args, scenario, canaries, session_ids, mode, reviewer, timeout)
    try:
        if args.reset:
            with httpx.Client(base_url=args.gateway.rstrip("/"), timeout=30.0) as ops:
                admin.reset_sandbox(ops)
        run = run_scenario(
            scenario,
            mode,
            args.gateway,
            canaries=canaries,
            session_ids=session_ids,
            reviewer=reviewer,
            poll_interval=args.poll_interval,
            review_timeout=timeout,
            log=print,
            step_delay=args.step_delay,
        )
    except (RunnerError, admin.AdminError, httpx.HTTPError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    result = scenario_result(run)
    print(f"sessions: {', '.join(run.session_ids)}")
    for step in result.steps:
        print(
            f"  step {step.step} {step.tool.value:13} expected={step.expected.value:6} "
            f"actual={step.actual.value:6} status={step.status.value:10} {'ok' if step.passed else 'MISMATCH'}"
        )
    print(f"scenario {'matched expected' if result.passed else 'did not match expected'}; attack_succeeded={result.attack_succeeded}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
