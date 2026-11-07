"""Security invariants: single handler call site, BLOCK never executes, fail closed."""
import ast
import json
from pathlib import Path

import pytest

from contracts.enums import Flag, ToolName, Verdict
from gateway import engine, tools

from .conftest import Driver, broad_scope

PACKAGE = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------- invariant 1: one call site


def _modules():
    for path in sorted(PACKAGE.rglob("*.py")):
        if "tests" in path.relative_to(PACKAGE).parts:
            continue
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def _parents(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_function(node, parents):
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return None


def test_handlers_are_called_from_exactly_one_place():
    registry_uses, handler_calls, direct_calls = [], [], []
    for path, tree in _modules():
        parents = _parents(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                if name.startswith("handle_"):
                    direct_calls.append((path.name, node.lineno))
                if isinstance(fn, ast.Name) and fn.id == "handler":
                    handler_calls.append((path.name, _enclosing_function(node, parents)))
            # any read of the registry other than its definition in tools.py
            if path.name != "tools.py":
                if (isinstance(node, ast.Name) and node.id == "HANDLERS") or (
                        isinstance(node, ast.Attribute) and node.attr == "HANDLERS"):
                    registry_uses.append((path.name, _enclosing_function(node, parents)))
    assert direct_calls == [], "handle_* functions must never be called directly"
    assert handler_calls == [("core.py", "execute")]
    assert registry_uses == [("core.py", "execute")]


def test_execute_is_a_method_of_gateway_and_nothing_else_is_called_handler_like():
    names = {fn.name for _, tree in _modules() for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef)}
    assert "execute" in names


def test_agent_never_imports_gateway_and_gateway_never_imports_agent():
    root = PACKAGE.parent
    for path, tree in _modules():
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            assert not any(m == "agent" or m.startswith("agent.") for m in mods), path
    agent_dir = root / "agent"
    if agent_dir.exists():
        for path in agent_dir.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods = [node.module]
                assert not any(m == "gateway" or m.startswith("gateway.") for m in mods), path


# ---------------------------------------------------------------- spy test: BLOCK never calls the handler


@pytest.fixture
def spy(monkeypatch):
    calls = []

    def install():
        for tool, real in list(tools.HANDLERS.items()):
            def make(real=real, tool=tool):
                def wrapper(env, args):
                    calls.append((tool, args))
                    return real(env, args)
                return wrapper
            monkeypatch.setitem(tools.HANDLERS, tool, make())
    install()
    return calls


def test_block_never_invokes_the_handler(gw, spy):
    drv = Driver(gw, broad_scope(allowed_tools=["file.read", "report.write", "db.query"],
                                 allowed_paths=["public/*"]))
    d = drv.do("file.read", {"path": "restricted/api_keys.txt"})
    assert (d.verdict, d.status.value) == (Verdict.BLOCK, "BLOCKED")
    d = drv.do("db.query", {"table": "salaries", "filter": {}})
    assert d.verdict is Verdict.BLOCK
    d = drv.do("report.write", {"name": "x", "content": "y"})  # two strikes: on watch, so REVIEW
    assert d.verdict is Verdict.REVIEW
    d = drv.do("file.read", {"path": "./RESTRICTED//api_keys.txt"})  # third strike
    assert d.verdict is Verdict.BLOCK
    d = drv.do("report.write", {"name": "y", "content": "z"})  # frozen
    assert (d.verdict, d.matched_rules) == (Verdict.BLOCK, ["R-STRIKES"])
    assert spy == []
    # every BLOCKED action id is absent from the executions table
    blocked = [r["action_id"] for r in gw.audit.list() if r["status"] == "BLOCKED"]
    assert len(blocked) == 4 and not set(blocked) & set(gw.audit.executions())
    assert gw.audit.executions() == []


def test_review_and_failclosed_never_invoke_the_handler(gw, spy):
    drv = Driver(gw)
    assert drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"}).verdict is Verdict.REVIEW
    assert drv.do("file.read", {"path": "../escape"}).status.value == "FAIL_CLOSED"
    assert drv.do("nope.tool", {}).status.value == "FAIL_CLOSED"
    assert spy == []
    assert gw.audit.executions() == []


def test_passthrough_does_invoke_the_handler_even_for_would_be_block(gw, spy):
    from contracts.enums import GatewayMode
    drv = Driver(gw, mode=GatewayMode.passthrough)
    d = drv.do("file.read", {"path": "restricted/api_keys.txt"})
    assert d.verdict is Verdict.ALLOW and d.status.value == "EXECUTED" and d.would_verdict is Verdict.BLOCK
    assert len(spy) == 1 and spy[0][0] is ToolName.file_read
    assert d.action_id in gw.audit.executions()
    d = drv.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})
    assert d.status.value == "EXECUTED" and d.would_verdict is Verdict.REVIEW and d.ticket_id is None
    assert len(spy) == 2


def test_executions_table_records_each_run_and_only_runs(gw):
    drv = Driver(gw)
    ok = drv.do("file.read", {"path": "public/product_faq.md"})
    blocked = drv.do("file.read", {"path": "restricted/api_keys.txt"})
    assert gw.audit.executions() == [ok.action_id]
    assert blocked.action_id not in gw.audit.executions()


# ---------------------------------------------------------------- invariant 2: fail closed


def assert_fail_closed(d):
    assert d.verdict is Verdict.BLOCK
    assert d.status.value == "FAIL_CLOSED"
    assert Flag.SYSTEM_FAIL_CLOSED in d.flags
    assert d.matched_rules == ["R-SYSTEM-FAIL-CLOSED"]
    assert d.action_id


def test_http_malformed_json_returns_fail_closed_decision(client):
    for body in (b"{not json", b"", b"[1,2]", b"null", b'"str"', b"\xff\xfe", b"{" * 5000):
        r = client.post("/actions/propose", content=body, headers={"content-type": "application/json"})
        assert r.status_code == 200, body
        assert_fail_closed(__import__("contracts.models", fromlist=["Decision"]).Decision(**r.json()))


@pytest.mark.parametrize("body", [
    {},
    {"session_id": "nope", "step": 1, "tool": "file.read", "args": {"path": "public/x"}, "agent_kind": "scripted"},
    {"session_id": 5, "step": "x", "tool": [], "args": 3, "agent_kind": None},
    {"tool": "file.read"},
])
def test_http_bad_bodies_never_422_or_500(client, body):
    r = client.post("/actions/propose", json=body)
    assert r.status_code == 200
    assert r.json()["status"] == "FAIL_CLOSED"


def test_unknown_tool_bad_args_and_engine_exception_fail_closed(gw, monkeypatch):
    drv = Driver(gw)
    assert_fail_closed(drv.do("shell.exec", {"cmd": "ls"}))
    assert_fail_closed(drv.do("file.read", {}))
    assert_fail_closed(drv.do("file.read", {"path": 5}))
    assert_fail_closed(drv.do("file.read", {"path": "public/x", "extra": 1}))
    assert_fail_closed(drv.do("file.read", {"path": "../../etc/passwd"}))
    assert_fail_closed(drv.do("file.read", {"path": "/etc/passwd"}))
    assert_fail_closed(drv.do("file.read", {"path": "public/a\x00b"}))
    assert_fail_closed(drv.do("db.query", {"table": "nope", "filter": {}}))
    assert_fail_closed(drv.do("db.query", {"table": "customers", "filter": {"a": {"x": 1}}}))
    assert_fail_closed(drv.do("email.draft", {"to": "not-an-email", "subject": "s", "body": "b"}))
    assert_fail_closed(drv.do("email.send", {"draft_id": "draft-missing"}))
    d = gw.propose({"session_id": "unknown-session", "step": 1, "tool": "file.read",
                    "args": {"path": "public/product_faq.md"}, "agent_kind": "scripted"})
    assert_fail_closed(d)

    def boom(*a, **k):
        raise RuntimeError("engine exploded with secret 919876543210")
    monkeypatch.setattr(engine, "evaluate", boom)
    d = drv.do("file.read", {"path": "public/product_faq.md"})
    assert_fail_closed(d)
    assert "919876543210" not in json.dumps(d.model_dump(mode="json"))
    # fail-closed blocks never count as strikes
    assert drv.session.strikes == 0


def test_send_requires_draft_from_same_session(gw):
    a, b = Driver(gw), Driver(gw)
    draft = a.draft("team@novacorp.local")
    assert_fail_closed(b.do("email.send", {"draft_id": draft}))
    assert a.do("email.send", {"draft_id": draft}).status.value == "EXECUTED"
    assert_fail_closed(a.do("email.send", {"draft_id": draft}))  # a draft cannot be sent twice


def test_fail_closed_is_audited(gw):
    drv = Driver(gw)
    d = drv.do("nope", {})
    rows = gw.audit.list(session_id=drv.sid)
    assert rows[-1]["action_id"] == d.action_id and rows[-1]["status"] == "FAIL_CLOSED"
    assert gw.audit.verify() == (True, None)


def test_file_read_handler_cannot_leave_sandbox_files(gw):
    drv = Driver(gw)
    prepared = gw._prepare(drv.session, ToolName.file_read, {"path": "public/product_faq.md"})
    prepared.args["path"] = "../novacorp.db"  # bypass normalization on purpose
    out = gw.execute(drv.session, prepared, "manual-action")
    assert not out.ok and out.error == "path is outside the sandbox"
