"""Spawn agent and eval subprocesses. The gateway never imports from /agent; it only starts the process."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Sequence


STEP_DELAY = "0.9"


class RunManager:
    def __init__(self, root: Path, log_dir: Path, gateway_url: str = "http://127.0.0.1:8000",
                 python: str | None = None, popen: Callable[..., subprocess.Popen] = subprocess.Popen) -> None:
        self.root = Path(root)
        self.log_dir = Path(log_dir)
        self.gateway_url = gateway_url
        self.python = python or sys.executable
        self._popen = popen
        self.lock = threading.Lock()
        self._procs: dict[str, list[subprocess.Popen]] = {}
        self.last_eval_id: str | None = None
        self.eval_id: str | None = None

    def busy(self) -> bool:
        return any(p.poll() is None for procs in self._procs.values() for p in procs)

    def eval_running(self) -> bool:
        return bool(self.eval_id) and any(p.poll() is None for p in self._procs.get(f"eval:{self.eval_id}", []))

    def eval_exit_code(self, report_id: str) -> int | None:
        procs = self._procs.get(f"eval:{report_id}", [])
        return procs[0].poll() if procs else None

    def eval_known(self, report_id: str) -> bool:
        return f"eval:{report_id}" in self._procs

    def _spawn(self, key: str, argv: Sequence[str], log_name: str) -> subprocess.Popen:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONPATH=str(self.root), PYTHONUNBUFFERED="1")
        with open(self.log_dir / log_name, "wb") as log:
            proc = self._popen(list(argv), cwd=str(self.root), env=env, stdout=log, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL)
        self._procs.setdefault(key, []).append(proc)
        return proc

    @staticmethod
    def _watch(proc: subprocess.Popen, session_ids: list[str], on_exit: Callable[[list[str]], None]) -> None:
        """Tell the gateway when an agent process ends, so the dashboard can show the run finished."""
        while proc.poll() is None:
            time.sleep(0.25)
        on_exit(session_ids)

    def start_run(self, scenario_id: str, agent_kind: str, sessions_by_mode: dict[str, list[str]],
                  on_exit: Callable[[list[str]], None] | None = None) -> str:
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        for mode, session_ids in sessions_by_mode.items():
            argv = [self.python, "-m", "agent.run", scenario_id, "--mode", mode, "--gateway", self.gateway_url,
                    "--session-ids", ",".join(session_ids), "--agent-kind", agent_kind, "--reviewer", "human"]
            if agent_kind == "scripted":
                argv += ["--step-delay", STEP_DELAY]  # pacing for a live audience; the eval never uses it
            proc = self._spawn(f"run:{run_id}", argv, f"{run_id}-{mode}.log")
            if on_exit is not None:
                threading.Thread(target=self._watch, args=(proc, list(session_ids), on_exit), daemon=True).start()
        return run_id

    def start_eval(self, report_id: str, with_llm: bool) -> None:
        argv = [self.python, "-m", "agent.eval", "--report-id", report_id, "--gateway", self.gateway_url]
        if with_llm:
            argv.append("--with-llm")
        self._spawn(f"eval:{report_id}", argv, f"{report_id}.log")
        self.eval_id = report_id
        self.last_eval_id = report_id

    def terminate_runs(self, grace_s: float = 3.0) -> int:
        """Stop active agent run processes (keys `run:*`). Never touches `eval:*`: the eval resets
        the sandbox between scenarios and must survive its own resets. Returns how many were stopped."""
        victims = [p for key, procs in self._procs.items() if key.startswith("run:")
                   for p in procs if p.poll() is None]
        for p in victims:
            try:
                p.terminate()
            except OSError:
                pass
        for p in victims:
            try:
                p.wait(timeout=grace_s)
            except Exception:  # noqa: BLE001
                try:
                    p.kill()
                except OSError:
                    pass
        return len(victims)

    def shutdown(self) -> None:
        for procs in self._procs.values():
            for p in procs:
                if p.poll() is None:
                    try:
                        p.terminate()
                    except OSError:
                        pass
        for procs in self._procs.values():
            for p in procs:
                try:
                    p.wait(timeout=3)
                except Exception:  # noqa: BLE001
                    try:
                        p.kill()
                    except OSError:
                        pass
