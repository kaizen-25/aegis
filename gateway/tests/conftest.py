from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore", message=".*httpx.*")

from fastapi.testclient import TestClient  # noqa: E402

from contracts.enums import GatewayMode, ToolName  # noqa: E402
from contracts.models import Decision, TaskScope  # noqa: E402
from gateway.app import Settings, create_app  # noqa: E402
from gateway.core import Gateway  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policies" / "novacorp.yaml"
SCENARIOS = ROOT / "scenarios"

ALL_TOOLS = [t for t in ToolName]


def broad_scope(**over) -> TaskScope:
    """A scope that allows everything, so a test can isolate one rule from R-SCOPE."""
    data = dict(task="test task", allowed_tools=ALL_TOOLS, allowed_paths=["*"],
                allowed_recipients=["*"], urgency="normal")
    data.update(over)
    return TaskScope(**data)


@pytest.fixture
def gw(tmp_path) -> Gateway:
    return Gateway(tmp_path / "sandbox", tmp_path / "audit.db", POLICY, SCENARIOS)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(sandbox_dir=tmp_path / "sandbox", audit_path=tmp_path / "audit.db",
                    policy_path=POLICY, scenarios_dir=SCENARIOS, reports_dir=tmp_path / "reports_out",
                    log_dir=tmp_path / "logs")


@pytest.fixture
def client(settings) -> TestClient:
    return TestClient(create_app(settings))


class Driver:
    """Small helper: one session, numbered steps."""

    def __init__(self, gw: Gateway, scope: TaskScope | None = None, mode=GatewayMode.protected,
                 scenario_id: str = "TEST"):
        self.gw = gw
        self.session = gw.create_session(scenario_id, scope or broad_scope(), mode)
        self.step = 0

    @property
    def sid(self) -> str:
        return self.session.session_id

    def do(self, tool: str, args: dict, note: str | None = None) -> Decision:
        self.step += 1
        body = {"session_id": self.sid, "step": self.step, "tool": tool, "args": args,
                "agent_kind": "scripted"}
        if note is not None:
            body["agent_note"] = note
        return self.gw.propose(body)

    def draft(self, to: str, body: str = "hello", subject: str = "subject") -> str:
        d = self.do("email.draft", {"to": to, "subject": subject, "body": body})
        assert d.result, d
        return d.result["draft_id"]


@pytest.fixture
def driver(gw):
    return Driver(gw)
