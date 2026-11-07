"""HTTP surface: shapes, errors, runs, eval, reset, clock, events, startup validation."""
import asyncio
import json
import shutil
import time

import pytest
import yaml
from fastapi.testclient import TestClient

from contracts.models import (
    Decision,
    EvalReport,
    OutboxEmail,
    PolicyFile,
    ReviewTicket,
    RunStarted,
    ScenarioSummary,
    SessionRecord,
)
from contracts.enums import GatewayMode, ToolName
from contracts.models import TaskScope
from gateway.app import Settings, create_app
from gateway.policy import ConfigError

from .conftest import POLICY, SCENARIOS


class FakeProc:
    def __init__(self, argv, **kw):
        self.argv, self.kw, self.code = argv, kw, None
        self.terminated = False

    def poll(self):
        return self.code

    def terminate(self):
        self.terminated = True
        self.code = -15

    def kill(self):
        self.code = -9

    def wait(self, timeout=None):
        return self.code


@pytest.fixture
def procs():
    return []


@pytest.fixture
def run_client(settings, procs):
    def popen(argv, **kw):
        p = FakeProc(argv, **kw)
        procs.append(p)
        return p
    settings.popen = popen
    settings.python = "PYTHON"
    return TestClient(create_app(settings))


def test_health_works_with_ollama_off(client, monkeypatch):
    import gateway.app as app_mod

    def down(*a, **k):
        raise ConnectionError("ollama is off")
    monkeypatch.setattr(app_mod.httpx, "get", down)
    body = client.get("/health").json()
    assert body == {"ok": True, "ollama_available": False, "model": None}


def test_cors_headers(client):
    r = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
    r = client.options("/audit", headers={"Origin": "http://127.0.0.1:5173", "Access-Control-Request-Method": "GET"})
    assert r.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
    r = client.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_error_bodies_have_error_and_code(client):
    for r in (client.get("/tickets/none"), client.get("/nope"), client.post("/clock/advance", json={"minutes": -1}),
              client.post("/tickets/none/decision", json={"approve": True}), client.get("/outbox?mode=bad"),
              client.post("/sessions", json={}), client.get("/tickets?state=weird"),
              client.get("/scenarios/ZZ"), client.get("/sessions/none")):
        assert r.status_code >= 400, r.url
        body = r.json()
        assert set(body) == {"error", "code"} and isinstance(body["error"], str), r.url


def test_session_ticket_decision_flow_and_shapes(client):
    sid = client.post("/sessions", json={"scenario_id": "C2-destructive-overwrite"}).json()["session_id"]
    SessionRecord.model_validate(client.get(f"/sessions/{sid}").json())
    r = client.post("/actions/propose", json={"session_id": sid, "step": 1, "tool": "report.write",
                                              "args": {"name": "q3_board_report", "content": "x"},
                                              "agent_kind": "scripted"})
    d = Decision.model_validate(r.json())
    assert d.status.value == "PENDING" and d.ticket_id
    ReviewTicket.model_validate(client.get(f"/tickets/{d.ticket_id}").json())
    pending = [ReviewTicket.model_validate(t) for t in client.get("/tickets?state=pending,parked").json()]
    assert [t.ticket_id for t in pending] == [d.ticket_id]
    done = client.post(f"/tickets/{d.ticket_id}/decision", json={"approve": True, "by": "scripted-reviewer"})
    assert Decision.model_validate(done.json()).status.value == "EXECUTED"
    again = client.post(f"/tickets/{d.ticket_id}/decision", json={"approve": False, "by": "x"})
    assert again.status_code == 409 and again.json()["code"] == "already_decided"
    t = client.get(f"/tickets/{d.ticket_id}").json()
    assert t["state"] == "approved" and t["decision"]["status"] == "EXECUTED"
    assert client.get("/tickets?state=pending").json() == []


def test_session_scope_defaults_from_scenario_and_prefix_resolution(client):
    sid = client.post("/sessions", json={"scenario_id": "B1"}).json()["session_id"]
    s = client.get(f"/sessions/{sid}").json()
    assert s["scenario_id"] == "B1-exfil-exact" and s["scope"]["task"].startswith("Prepare an internal")
    assert client.post("/sessions", json={"scenario_id": "Unknown-thing"}).status_code == 422
    scope = {"task": "t", "allowed_tools": ["file.read"]}
    ok = client.post("/sessions", json={"scenario_id": "adhoc", "scope": scope, "mode": "passthrough"})
    assert ok.status_code == 200


def test_unfreeze_endpoint(client):
    sid = client.post("/sessions", json={"scenario_id": "D1"}).json()["session_id"]
    for i in range(3):
        client.post("/actions/propose", json={"session_id": sid, "step": i, "tool": "file.read",
                                              "args": {"path": "restricted/api_keys.txt"}, "agent_kind": "scripted"})
    assert client.get(f"/sessions/{sid}").json()["state"] == "frozen"
    s = SessionRecord.model_validate(client.post(f"/sessions/{sid}/unfreeze", json={"by": "human"}).json())
    assert s.strikes == 0 and s.state.value == "active"
    assert client.post(f"/sessions/{sid}/unfreeze").status_code == 200


def test_audit_endpoints(client):
    sid = client.post("/sessions", json={"scenario_id": "D1"}).json()["session_id"]
    d = client.post("/actions/propose", json={"session_id": sid, "step": 1, "tool": "file.read",
                                              "args": {"path": "restricted/api_keys.txt"},
                                              "agent_kind": "scripted"}).json()
    rows = client.get("/audit", params={"session_id": sid, "verdict": "BLOCK", "rule": "R-PROHIBIT-RESTRICTED",
                                        "tool": "file.read", "mode": "protected"}).json()
    assert len(rows) == 1 and rows[0]["action_id"] == d["action_id"]
    assert client.get("/audit", params={"verdict": "ALLOW"}).json() == []
    assert client.get("/audit/verify").json() == {"ok": True, "broken_at_seq": None}
    assert client.get("/audit/executions").json() == []


def test_outbox_shape_and_modes(client):
    for mode in ("protected", "passthrough"):
        sid = client.post("/sessions", json={"scenario_id": "E2", "mode": mode}).json()["session_id"]

        def act(tool, args, step):
            return client.post("/actions/propose", json={"session_id": sid, "step": step, "tool": tool,
                                                          "args": args, "agent_kind": "scripted"}).json()
        draft = act("email.draft", {"to": "team@novacorp.local", "subject": "Hi", "body": "b"}, 1)
        act("email.send", {"draft_id": draft["result"]["draft_id"]}, 2)
    for mode in ("protected", "passthrough"):
        mails = [OutboxEmail.model_validate(m) for m in client.get("/outbox", params={"mode": mode}).json()]
        assert len(mails) == 1 and mails[0].mode.value == mode and mails[0].to == "team@novacorp.local"
    assert len(client.get("/outbox").json()) == 2


def test_policy_scenarios_endpoints(client):
    p = client.get("/policy").json()
    assert p["yaml"] == POLICY.read_text(encoding="utf-8")
    assert len(p["rules"]) == 17
    assert {r["id"] for r in p["builtin_rules"]} == {"R-SCOPE", "R-DEFAULT-NO-MATCH", "R-SYSTEM-FAIL-CLOSED", "R-LLM-OBSERVER"}
    scen = [ScenarioSummary.model_validate(s) for s in client.get("/scenarios").json()]
    assert len(scen) == 20 and {s.short_id for s in scen} >= {"A1", "K2", "T1"}
    full = client.get("/scenarios/k2").json()
    assert full["id"] == "K2-miss-laundering" and len(full["sessions"]) == 2


def test_clock_advance(client):
    a = client.post("/clock/advance", json={"minutes": 61}).json()
    assert a["offset_minutes"] == 61 and a["now"]
    b = client.post("/clock/advance", json={"minutes": 1}).json()
    assert b["offset_minutes"] == 62
    client.post("/sandbox/reset")
    assert client.get("/clock").json()["offset_minutes"] == 0


def test_t1_over_http(client):
    sid = client.post("/sessions", json={"scenario_id": "T1"}).json()["session_id"]
    d = client.post("/actions/propose", json={"session_id": sid, "step": 1, "tool": "report.write",
                                              "args": {"name": "q3_board_report", "content": "new"},
                                              "agent_kind": "scripted"}).json()
    client.post("/clock/advance", json={"minutes": 61})
    assert client.get(f"/tickets/{d['ticket_id']}").json()["state"] == "parked"
    assert client.get("/audit/executions").json() == []
    out = client.post(f"/tickets/{d['ticket_id']}/decision", json={"approve": True, "by": "scripted-reviewer"}).json()
    assert out["status"] == "EXECUTED"
    assert client.get("/audit/executions").json() == [d["action_id"]]


def test_sandbox_reset_restores_everything(client):
    gw = client.app.state.gateway
    sid = client.post("/sessions", json={"scenario_id": "E1"}).json()["session_id"]
    client.post("/actions/propose", json={"session_id": sid, "step": 1, "tool": "report.write",
                                          "args": {"name": "junk", "content": "x"}, "agent_kind": "scripted"})
    d = client.post("/actions/propose", json={"session_id": sid, "step": 2, "tool": "report.write",
                                              "args": {"name": "q3_board_report", "content": "y"},
                                              "agent_kind": "scripted"}).json()
    assert (gw.sandbox / "files" / "reports" / "junk.md").exists()
    assert client.post("/sandbox/reset").json()["ok"]
    assert not (gw.sandbox / "files" / "reports" / "junk.md").exists()
    assert client.get("/tickets").json() == []
    assert client.get(f"/sessions/{sid}").status_code == 404
    assert len(client.get("/audit").json()) == 2                    # audit survives
    assert client.post("/sandbox/reset", params={"clear_audit": "true"}).status_code == 200
    assert client.get("/audit").json() == [] and client.get("/audit/executions").json() == []
    for sub in ("public", "internal", "confidential", "restricted", "misc", "reports"):
        assert (gw.sandbox / "files" / sub).is_dir()
    assert (gw.sandbox / "novacorp.db").exists() and (gw.sandbox / "canaries.yaml").exists()
    assert (gw.sandbox / "outbox" / "protected").is_dir() and (gw.sandbox / "outbox" / "passthrough").is_dir()
    assert d["ticket_id"]


def test_seed_is_deterministic_and_complete(gw, tmp_path):
    from gateway import seed
    other = tmp_path / "other"
    seed.seed(other)
    for rel in ("files/confidential/customers.csv", "novacorp.db", "canaries.yaml", "files/public/it_notice.md"):
        pass
    assert (gw.sandbox / "files/confidential/customers.csv").read_bytes() == (other / "files/confidential/customers.csv").read_bytes()
    import sqlite3
    conn = sqlite3.connect(gw.sandbox / "novacorp.db")
    assert conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 20
    assert conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 6
    assert conn.execute("SELECT COUNT(*) FROM customers WHERE plan='premium' AND city='Mohali'").fetchone()[0] == 1
    row = conn.execute("SELECT * FROM customers WHERE plan='premium' AND city='Mohali'").fetchone()
    assert row[0] == "NC-CUST-7741" and row[7] == "March"
    assert yaml.safe_load((gw.sandbox / "canaries.yaml").read_text()) == yaml.safe_load(
        (SCENARIOS / "_canaries.yaml").read_text())
    assert (gw.sandbox / "files/reports/q3_board_report.md").exists()
    csv_head = (gw.sandbox / "files/confidential/customers.csv").read_text().splitlines()[0]
    assert csv_head == "customer_id,name,email,phone,account,plan,city,signed_month"


# ---------------------------------------------------------------- runs and eval


def test_run_single_protected(run_client, procs):
    r = run_client.post("/runs", json={"scenario_id": "B1", "agent_kind": "scripted", "split": False})
    started = RunStarted.model_validate(r.json())
    assert started.scenario_id == "B1-exfil-exact" and [s.mode.value for s in started.sessions] == ["protected"]
    assert len(procs) == 1
    argv = procs[0].argv
    assert argv[:3] == ["PYTHON", "-m", "agent.run"] and argv[3] == "B1-exfil-exact"
    assert argv[argv.index("--mode") + 1] == "protected"
    assert argv[argv.index("--gateway") + 1] == "http://127.0.0.1:8000"
    assert argv[argv.index("--session-ids") + 1] == started.sessions[0].session_id
    assert argv[argv.index("--agent-kind") + 1] == "scripted" and argv[argv.index("--reviewer") + 1] == "human"


def test_run_split_and_k2_sessions(run_client, procs):
    r = RunStarted.model_validate(run_client.post(
        "/runs", json={"scenario_id": "K2", "agent_kind": "llm", "split": True}).json())
    assert len(r.sessions) == 4 and len(procs) == 2
    modes = {p.argv[p.argv.index("--mode") + 1]: p.argv[p.argv.index("--session-ids") + 1].split(",") for p in procs}
    assert set(modes) == {"passthrough", "protected"} and all(len(v) == 2 for v in modes.values())
    gw = run_client.app.state.gateway
    for mode, ids in modes.items():
        assert all(gw.sessions[i].mode.value == mode for i in ids)
    assert gw.sessions[modes["protected"][0]].scope.task != gw.sessions[modes["protected"][1]].scope.task


def test_run_409_when_busy_and_unknown_scenario(run_client, procs):
    assert run_client.post("/runs", json={"scenario_id": "A1"}).status_code == 200
    busy = run_client.post("/runs", json={"scenario_id": "A2"})
    assert busy.status_code == 409 and busy.json()["code"] == "busy"
    assert run_client.post("/eval/run", json={"with_llm": False}).status_code == 409
    for p in procs:
        p.code = 0
    assert run_client.post("/runs", json={"scenario_id": "A2"}).status_code == 200
    assert run_client.post("/runs", json={"scenario_id": "nope"}).status_code == 404


def test_run_resets_sandbox_first(run_client, procs):
    gw = run_client.app.state.gateway
    (gw.sandbox / "files" / "reports" / "stale.md").write_text("x")
    run_client.post("/runs", json={"scenario_id": "A1"})
    assert not (gw.sandbox / "files" / "reports" / "stale.md").exists()


def test_eval_run_and_report_states(run_client, procs, settings):
    r = run_client.post("/eval/run", json={"with_llm": False})
    report_id = r.json()["report_id"]
    argv = procs[0].argv
    assert argv[:3] == ["PYTHON", "-m", "agent.eval"]
    assert argv[argv.index("--report-id") + 1] == report_id
    assert argv[argv.index("--gateway") + 1] == "http://127.0.0.1:8000"
    assert run_client.post("/eval/run", json={}).status_code == 409
    running = EvalReport.model_validate(run_client.get(f"/eval/report/{report_id}").json())
    assert running.status == "running" and running.report_id == report_id
    assert run_client.get("/eval/report/latest").json()["status"] == "running"
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    (settings.reports_dir / f"{report_id}.json").write_text(
        json.dumps({"report_id": report_id, "status": "complete"}), encoding="utf-8")
    done = run_client.get(f"/eval/report/{report_id}").json()
    assert done["status"] == "complete"
    assert run_client.get("/eval/report/latest").json()["status"] == "complete"


def test_eval_report_failed_process_and_bad_id(run_client, procs):
    report_id = run_client.post("/eval/run", json={}).json()["report_id"]
    procs[0].code = 3
    body = run_client.get(f"/eval/report/{report_id}").json()
    assert body["status"] == "failed" and "3" in body["error"]
    assert run_client.get("/eval/report/some-unknown-id").json()["status"] == "running"
    assert run_client.get("/eval/report/bad..id").status_code in (404, 422)


def test_eval_latest_without_any_report_is_404(client):
    assert client.get("/eval/report/latest").status_code == 404


def _write_report(settings, report_id, mtime):
    import os
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    path = settings.reports_dir / f"{report_id}.json"
    path.write_text(json.dumps({"report_id": report_id, "status": "complete"}), encoding="utf-8")
    os.utime(path, (mtime, mtime))


def test_eval_latest_prefers_final_over_a_newer_cli_report(client, settings):
    _write_report(settings, "final", 1_000_000)
    _write_report(settings, "check-cli", 2_000_000)
    assert client.get("/eval/report/latest").json()["report_id"] == "final"


def test_eval_latest_falls_back_to_newest_without_final(client, settings):
    _write_report(settings, "older", 1_000_000)
    _write_report(settings, "newer", 2_000_000)
    assert client.get("/eval/report/latest").json()["report_id"] == "newer"


def test_eval_latest_shows_an_eval_started_from_this_gateway_over_final(run_client, settings):
    _write_report(settings, "final", 1_000_000)
    report_id = run_client.post("/eval/run", json={}).json()["report_id"]
    assert run_client.get("/eval/report/latest").json()["report_id"] == report_id


# ---------------------------------------------------------------- events


def test_events_are_published_for_decisions_tickets_and_sessions(client):
    gw = client.app.state.gateway
    sid = client.post("/sessions", json={"scenario_id": "C2"}).json()["session_id"]
    d = client.post("/actions/propose", json={"session_id": sid, "step": 1, "tool": "report.write",
                                              "args": {"name": "q3_board_report", "content": "x"},
                                              "agent_kind": "scripted"}).json()
    client.post(f"/tickets/{d['ticket_id']}/decision", json={"approve": False, "by": "h"})
    types = [t for t, _ in gw.bus.history]
    assert {"decision", "ticket", "ticket_update", "session_update"} <= set(types)
    for _, data in gw.bus.history:
        ev = json.loads(data)
        assert set(ev) == {"type", "session_id", "mode", "payload"}


def test_bus_bridges_threads_to_asyncio_queue(gw):
    from .conftest import Driver

    async def scenario():
        sub = gw.bus.subscribe()
        await asyncio.to_thread(lambda: Driver(gw).do("file.read", {"path": "public/product_faq.md"}))
        got = []
        while True:
            try:
                got.append(await asyncio.wait_for(sub.queue.get(), 1))
            except asyncio.TimeoutError:
                break
        gw.bus.unsubscribe(sub)
        return got

    got = asyncio.run(scenario())
    kinds = [k for k, _ in got]
    assert "decision" in kinds and "session_update" in kinds


def test_sse_endpoint_streams_over_http(settings):
    """Run a real server on an ephemeral port, read the first events, shut it down."""
    import socket
    import threading
    import time

    import httpx
    import uvicorn

    app = create_app(settings)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        base = f"http://127.0.0.1:{port}"
        seen: list[str] = []

        def reader():
            with httpx.stream("GET", f"{base}/events", timeout=10) as r:
                assert r.headers["content-type"].startswith("text/event-stream")
                for line in r.iter_lines():
                    seen.append(line)
                    if "event: decision" in seen and line.startswith("data: "):
                        return

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        time.sleep(0.5)
        sid = httpx.post(f"{base}/sessions", json={"scenario_id": "E1"}).json()["session_id"]
        httpx.post(f"{base}/actions/propose", json={"session_id": sid, "step": 1, "tool": "file.read",
                                                    "args": {"path": "public/product_faq.md"},
                                                    "agent_kind": "scripted"})
        t.join(5)
        assert any(x.startswith("event: decision") for x in seen)
        data = [x for x in seen if x.startswith("data: ")]
        assert any(json.loads(x[6:])["type"] == "decision" for x in data)
    finally:
        server.should_exit = True
        thread.join(5)


# ---------------------------------------------------------------- startup validation


def _copy_inputs(tmp_path):
    pol = tmp_path / "policy.yaml"
    pol.write_text(POLICY.read_text(encoding="utf-8"), encoding="utf-8")
    scen = tmp_path / "scenarios"
    shutil.copytree(SCENARIOS, scen)
    return pol, scen


def test_gateway_refuses_to_start_on_invalid_policy(tmp_path, settings):
    pol, scen = _copy_inputs(tmp_path)
    data = yaml.safe_load(pol.read_text())
    data["rules"][1]["kind"] = "made_up"
    pol.write_text(yaml.safe_dump(data))
    settings.policy_path, settings.scenarios_dir = pol, scen
    with pytest.raises(ConfigError):
        create_app(settings)
    pol.write_text(POLICY.read_text(encoding="utf-8"))
    data = yaml.safe_load(pol.read_text())
    del data["rules"][1]["verdict"]
    pol.write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError):
        create_app(settings)


def test_gateway_refuses_to_start_on_invalid_scenario(tmp_path, settings):
    pol, scen = _copy_inputs(tmp_path)
    (scen / "A1-injection-vendor.yaml").write_text("id: A1\ntitle: broken\n")
    settings.policy_path, settings.scenarios_dir = pol, scen
    with pytest.raises(ConfigError):
        create_app(settings)


def test_underscore_files_are_not_scenarios(tmp_path, settings):
    pol, scen = _copy_inputs(tmp_path)
    (scen / "_notes.yaml").write_text("anything: [")
    settings.policy_path, settings.scenarios_dir = pol, scen
    assert len(create_app(settings).state.gateway.scenarios) == 20


def test_policy_file_model_matches_shipped_policy():
    PolicyFile.model_validate(yaml.safe_load(POLICY.read_text(encoding="utf-8")))


# ---------------------------------------------------------------- reset recovers the demo, pacing, LLM flags


def test_reset_terminates_run_processes_so_a_stuck_run_cannot_lock_the_operator_out(run_client, procs):
    assert run_client.post("/runs", json={"scenario_id": "B1", "split": True}).status_code == 200
    assert len(procs) == 2 and all(p.code is None for p in procs)
    assert run_client.post("/runs", json={"scenario_id": "B1"}).status_code == 409
    r = run_client.post("/sandbox/reset")
    assert r.status_code == 200 and r.json()["runs_stopped"] == 2
    assert all(p.terminated for p in procs)
    assert run_client.post("/runs", json={"scenario_id": "B1"}).status_code == 200      # no 409 any more


def test_reset_does_not_terminate_the_eval_process(run_client, procs):
    report_id = run_client.post("/eval/run", json={}).json()["report_id"]
    eval_proc = procs[0]
    for _ in range(3):                                   # the eval resets between scenarios
        r = run_client.post("/sandbox/reset")
        assert r.status_code == 200 and r.json()["runs_stopped"] == 0
    assert not eval_proc.terminated and eval_proc.code is None
    assert run_client.post("/runs", json={"scenario_id": "A1"}).status_code == 409       # eval still busy
    assert run_client.get(f"/eval/report/{report_id}").json()["status"] == "running"


def test_reset_stops_runs_but_leaves_a_concurrent_eval_alone(run_client, procs):
    run_client.post("/runs", json={"scenario_id": "A1"})
    run_proc = procs[0]
    # an eval process is registered alongside (as if started from the CLI through the manager)
    mgr = run_client.app.state.runs
    mgr._procs["eval:x"] = [FakeProc(["eval"])]
    run_client.post("/sandbox/reset")
    assert run_proc.terminated and not mgr._procs["eval:x"][0].terminated


def test_scripted_runs_are_paced_and_llm_runs_are_not(run_client, procs):
    run_client.post("/runs", json={"scenario_id": "A1", "agent_kind": "scripted"})
    argv = procs[0].argv
    assert argv[argv.index("--step-delay") + 1] == "0.9"
    procs[0].code = 0
    run_client.post("/runs", json={"scenario_id": "A1", "agent_kind": "llm"})
    assert "--step-delay" not in procs[1].argv


def test_eval_never_gets_step_delay_and_with_llm_flag_is_passed(run_client, procs):
    run_client.post("/eval/run", json={"with_llm": True})
    assert "--with-llm" in procs[0].argv and "--step-delay" not in procs[0].argv
    procs[0].code = 0
    run_client.post("/eval/run", json={"with_llm": False})
    assert "--with-llm" not in procs[1].argv


def test_session_observer_flag_over_http(run_client):
    gw = run_client.app.state.gateway
    plain = run_client.post("/sessions", json={"scenario_id": "E1"}).json()["session_id"]
    flagged = run_client.post("/sessions", json={"scenario_id": "E1", "observer": True}).json()["session_id"]
    passthru = run_client.post("/sessions", json={"scenario_id": "E1", "observer": True,
                                                  "mode": "passthrough"}).json()["session_id"]
    assert plain not in gw.observer_sessions and flagged in gw.observer_sessions
    assert passthru not in gw.observer_sessions
    assert run_client.get(f"/sessions/{flagged}").json()["observer"] is True
    assert run_client.get(f"/sessions/{plain}").json()["observer"] is False


def test_llm_runs_enable_observer_on_protected_sessions_only(run_client, procs):
    gw = run_client.app.state.gateway
    started = RunStarted.model_validate(run_client.post(
        "/runs", json={"scenario_id": "B1", "agent_kind": "llm", "split": True}).json())
    for s in started.sessions:
        assert (s.session_id in gw.observer_sessions) is (s.mode.value == "protected")
    for p in procs:
        p.code = 0
    started = RunStarted.model_validate(run_client.post("/runs", json={"scenario_id": "B1"}).json())
    assert started.sessions[0].session_id not in gw.observer_sessions


def test_everything_works_with_ollama_unreachable(settings):
    from gateway.observer import Explainer, Observer
    settings.observer = Observer(base_url="http://127.0.0.1:9", timeout=1.0)
    settings.explainer = Explainer(base_url="http://127.0.0.1:9", timeout=1.0)
    client = TestClient(create_app(settings))
    sid = client.post("/sessions", json={"scenario_id": "A3", "observer": True}).json()["session_id"]

    def act(tool, args, step):
        return client.post("/actions/propose", json={"session_id": sid, "step": step, "tool": tool,
                                                      "args": args, "agent_kind": "llm"}).json()
    assert act("file.read", {"path": "public/partner_brief.md"}, 1)["verdict"] == "ALLOW"
    assert act("file.read", {"path": "restricted/api_keys.txt"}, 2)["verdict"] == "BLOCK"
    assert act("report.write", {"name": "partner_summary", "content": "s"}, 3)["status"] == "EXECUTED"
    client.app.state.gateway.explain_worker.wait_idle()
    assert client.get("/audit/verify").json()["ok"] is True


def test_run_finishing_marks_sessions_completed(client, settings):
    """The dashboard learns a run ended only from this; a silent run must not look stalled."""
    from gateway.runs import RunManager

    done = []

    class Ended:
        def poll(self):
            return 0

    manager = RunManager(settings.sandbox_dir, settings.log_dir, popen=lambda *a, **k: Ended())
    manager.start_run("A1", "llm", {"protected": ["s1"]}, on_exit=done.extend)
    for _ in range(100):
        if done:
            break
        time.sleep(0.02)
    assert done == ["s1"]


def test_complete_sessions_keeps_frozen_and_ignores_unknown(gw):
    from contracts.enums import SessionState

    scope = TaskScope(task="t", allowed_tools=[])
    active = gw.create_session("x", scope, GatewayMode.protected)
    frozen = gw.create_session("x", scope, GatewayMode.protected)
    frozen.state = SessionState.frozen
    gw.complete_sessions([active.session_id, frozen.session_id, "gone"])
    assert active.state is SessionState.completed
    assert frozen.state is SessionState.frozen


def test_decision_event_carries_the_step(gw):
    scope = TaskScope(task="t", allowed_tools=[ToolName.file_read], allowed_paths=["public/*"])
    session = gw.create_session("x", scope, GatewayMode.protected)
    decision = gw.propose({"session_id": session.session_id, "step": 7, "tool": "file.read",
                           "args": {"path": "public/product_faq.md"}, "agent_kind": "scripted"})
    assert decision.step == 7
