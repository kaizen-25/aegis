"""Live-agent tests with a FAKE Ollama and a FAKE gateway (httpx.MockTransport).

Nothing here talks to a real model. They prove the loop, the wire format, the error handling
and the canary guard. Real-model behaviour is covered by the manual CP4 runs, not by these.
"""
from __future__ import annotations

import copy
import json

import httpx
import pytest

from agent import eval as agent_eval
from agent import llm_agent as llm
from agent import run as agent_run
from agent.runner import AgentClient, run_scenario
from agent.scenarios import find_scenario, load_all, load_canaries
from contracts.enums import ExecStatus, GatewayMode, ToolName, Verdict

CANARIES = load_canaries()
SCENARIOS = load_all()
A1 = find_scenario("A1", SCENARIOS)


# Fakes ---------------------------------------------------------------------------------


class FakeChat:
    """Stands in for Ollama: returns scripted replies and records everything it was sent."""

    model = "fake-model"

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent: list[str] = []  # JSON of the messages, copied at call time
        self.calls = 0

    def chat(self, messages, tools):
        self.calls += 1
        self.sent.append(json.dumps(copy.deepcopy(messages)))
        reply = self.replies.pop(0) if self.replies else self.replies_default
        return {"message": reply}

    replies_default = {"role": "assistant", "content": "done"}


def call(name, **args):
    return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}


DONE = {"role": "assistant", "content": "All done."}


class FakeGateway:
    """Minimal gateway: verdicts chosen by the test, requests recorded."""

    def __init__(self, decide, ticket_states=("pending", "rejected")):
        self.decide = decide
        self.proposals: list[dict] = []
        self.paths: list[tuple[str, str]] = []
        self.ticket_states = list(ticket_states)
        self.sessions_created = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.paths.append((request.method, request.url.path))
        if request.url.path == "/sessions":
            self.sessions_created += 1
            return httpx.Response(200, json={"session_id": "sess-1"})
        if request.url.path == "/actions/propose":
            body = json.loads(request.content)
            self.proposals.append(body)
            return httpx.Response(200, json=self.decide(body, len(self.proposals)))
        if request.url.path.startswith("/tickets/"):
            state = self.ticket_states.pop(0) if len(self.ticket_states) > 1 else self.ticket_states[0]
            return httpx.Response(200, json=ticket_json(state))
        return httpx.Response(404, json={"error": "no", "code": "not_found"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler), base_url="http://gateway.test")


def ticket_json(state):
    return {
        "ticket_id": "t1",
        "action_id": "a1",
        "session_id": "sess-1",
        "created_at": "2026-10-31T10:00:00Z",
        "risk": "medium",
        "urgency": "normal",
        "rule_id": "R-SCOPE",
        "impact_if_approved": "x",
        "impact_if_rejected": "y",
        "state": state,
    }


def decision(verdict="ALLOW", status="EXECUTED", **extra):
    base = {"action_id": "a1", "verdict": verdict, "status": status, "explanation": "because", "latency_ms": 1.5}
    base.update(extra)
    return base


def run_agent(chat, gateway, **kwargs):
    return llm.run_llm_agent(
        A1,
        GatewayMode.protected,
        "http://gateway.test",
        chat=chat,
        canaries=CANARIES,
        http_client=gateway.client(),
        poll_interval=0.0,
        sleep=lambda _s: None,
        **kwargs,
    )


# Tools ----------------------------------------------------------------------------------


def test_all_six_tools_offered_with_function_safe_names():
    tools = llm.tool_definitions()
    names = [t["function"]["name"] for t in tools]
    assert names == ["file_read", "report_write", "db_query", "db_delete", "email_draft", "email_send"]
    assert all(t["type"] == "function" for t in tools)
    assert all("." not in n for n in names)
    assert {llm._BY_FUNCTION[n] for n in names} == set(ToolName)


def test_argument_schemas_follow_the_contract():
    by_name = {t["function"]["name"]: t["function"]["parameters"] for t in llm.tool_definitions()}
    assert set(by_name["file_read"]["properties"]) == {"path"}
    assert set(by_name["report_write"]["properties"]) == {"name", "content"}
    assert set(by_name["db_query"]["properties"]) == {"table", "filter"}
    assert set(by_name["db_delete"]["properties"]) == {"table", "record_id"}
    assert set(by_name["email_draft"]["properties"]) == {"to", "subject", "body"}
    assert set(by_name["email_send"]["properties"]) == {"draft_id"}
    for params in by_name.values():
        assert set(params["required"]) <= set(params["properties"])


def test_system_prompt_has_no_instruction_about_documents():
    text = llm.SYSTEM_PROMPT.lower()
    for word in ("ignore", "obey", "instruction", "untrusted", "inject"):
        assert word not in text


# Loop -----------------------------------------------------------------------------------


def test_loop_proposes_with_llm_kind_and_reports_review_outcome():
    def decide(body, n):
        if n == 1:
            return decision(result={"content": "proposal text"}, flags=["UNTRUSTED_CONTENT"])
        return decision("REVIEW", "PENDING", ticket_id="t1", flags=["OFF_TASK"], matched_rules=["R-SCOPE"])

    gw = FakeGateway(decide)
    chat = FakeChat([
        call("file_read", path="public/vendor_proposal.md"),
        call("db_query", table="customers", filter={"customer_id": "NC-CUST-7741"}),
        DONE,
    ])
    run = run_agent(chat, gw)
    assert [p["tool"] for p in gw.proposals] == ["file.read", "db.query"]
    assert [p["step"] for p in gw.proposals] == [1, 2]
    assert all(p["agent_kind"] == "llm" and p["session_id"] == "sess-1" for p in gw.proposals)
    assert run.stopped == "model finished" and run.final_message == "All done."
    assert run.steps[1].verdict == Verdict.REVIEW and run.steps[1].flags == ["OFF_TASK"]
    assert run.steps[1].ticket_state == "rejected"
    last_seen = chat.sent[-1]
    assert "rejected" in last_seen and "was not performed" in last_seen
    assert "proposal text" in chat.sent[1]  # the model gets the (masked) tool result back
    assert chat.calls == 3


def test_agent_uses_only_the_three_allowed_gateway_calls():
    gw = FakeGateway(lambda b, n: decision("REVIEW", "PENDING", ticket_id="t1"))
    run_agent(FakeChat([call("db_query", table="customers", filter={}), DONE]), gw)
    for method, path in gw.paths:
        assert (method, path) in {("POST", "/sessions"), ("POST", "/actions/propose")} or (
            method == "GET" and path.startswith("/tickets/")
        )


def test_block_is_reported_to_the_model():
    gw = FakeGateway(lambda b, n: decision("BLOCK", "BLOCKED", explanation="Restricted files can never be read"))
    chat = FakeChat([call("file_read", path="restricted/api_keys.txt"), DONE])
    run_agent(chat, gw)
    assert "blocked" in chat.sent[1].lower()
    assert "BLOCK" in chat.sent[1]


def test_unknown_tool_is_still_proposed_so_the_gateway_fails_it_closed():
    gw = FakeGateway(lambda b, n: decision("BLOCK", "FAIL_CLOSED", explanation="unknown tool"))
    run = run_agent(FakeChat([call("shell_exec", cmd="rm -rf /"), DONE]), gw)
    assert gw.proposals[0]["tool"] == "shell_exec"
    assert gw.proposals[0]["args"] == {"cmd": "rm -rf /"}
    assert run.steps[0].status == "FAIL_CLOSED"


def test_stops_after_eight_steps():
    gw = FakeGateway(lambda b, n: decision(result={"ok": True}))
    chat = FakeChat([call("file_read", path="public/a.md")] * 20)
    run = run_agent(chat, gw)
    assert len(gw.proposals) == 8 and chat.calls == 8
    assert run.stopped == "step limit"


def test_no_tool_call_stops_immediately_with_no_fake_steps():
    gw = FakeGateway(lambda b, n: decision())
    run = run_agent(FakeChat([DONE]), gw)
    assert run.steps == [] and gw.proposals == []


def test_arguments_given_as_a_string_are_parsed_and_bad_ones_are_forwarded_for_fail_closed():
    gw = FakeGateway(lambda b, n: decision("BLOCK", "FAIL_CLOSED"))
    string_args = {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "file_read", "arguments": '{"path": "x"}'}}]}
    garbage = {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "file_read", "arguments": "not json"}}]}
    run_agent(FakeChat([string_args, garbage, DONE]), gw)
    assert gw.proposals[0]["args"] == {"path": "x"}
    assert gw.proposals[1]["args"] == {"raw_arguments": "not json"}


def test_malformed_tool_call_is_an_error_not_a_guess():
    gw = FakeGateway(lambda b, n: decision())
    bad = {"role": "assistant", "content": "", "tool_calls": [{"nope": 1}]}
    with pytest.raises(llm.LlmError):
        run_agent(FakeChat([bad]), gw)
    assert gw.proposals == []


def test_existing_session_id_is_honoured():
    gw = FakeGateway(lambda b, n: decision())
    run_agent(FakeChat([call("file_read", path="public/a.md"), DONE]), gw, session_ids=["from-runs"])
    assert gw.sessions_created == 0
    assert gw.proposals[0]["session_id"] == "from-runs"


def test_scenario_without_prompt_is_refused_before_any_gateway_call():
    gw = FakeGateway(lambda b, n: decision())
    b1 = find_scenario("B1", SCENARIOS)
    with pytest.raises(llm.LlmError, match="llm_prompt"):
        llm.run_llm_agent(b1, GatewayMode.protected, "http://gateway.test", chat=FakeChat([]), canaries=CANARIES, http_client=gw.client())
    assert gw.paths == []


# Canary guard ---------------------------------------------------------------------------


def test_no_raw_canary_is_ever_sent_to_the_model():
    leak = " ".join(CANARIES.values())
    gw = FakeGateway(
        lambda b, n: decision(
            result={"content": f"contact {leak}", "rows": [{"email": CANARIES["email_1"], "phone": CANARIES["phone_1"]}]},
            explanation=f"saw {CANARIES['account_1']}",
        )
    )
    chat = FakeChat([call("file_read", path="public/a.md"), call("db_query", table="customers", filter={}), DONE])
    run_agent(chat, gw)
    everything = "\n".join(chat.sent)
    for name, value in CANARIES.items():
        assert value not in everything, f"canary {name} reached the model"
    assert llm.REDACTED in everything


def test_scenario_prompts_contain_no_canary_values():
    for s in SCENARIOS:
        for value in CANARIES.values():
            assert value not in (s.llm_prompt or ""), s.id
    assert all(value not in llm.SYSTEM_PROMPT for value in CANARIES.values())


# Ollama client -------------------------------------------------------------------------


def ollama(handler):
    return llm.OllamaClient(http=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://ollama.test"))


def test_request_payload_matches_the_spec():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        seen["path"] = request.url.path
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "hi"}})

    client = ollama(handler)
    assert client.model == "qwen2.5:7b-instruct-q4_K_M"
    client.chat([{"role": "user", "content": "x"}], llm.tool_definitions())
    assert seen["path"] == "/api/chat"
    assert seen["stream"] is False and seen["keep_alive"] == -1
    assert seen["options"] == {"num_ctx": 8192, "temperature": 0, "seed": 42}
    assert len(seen["tools"]) == 6 and seen["model"] == "qwen2.5:7b-instruct-q4_K_M"
    assert llm.FALLBACK_MODEL == "qwen2.5:3b-instruct-q4_K_M"


@pytest.mark.parametrize(
    "handler, text",
    [
        (lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")), "failed"),
        (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow")), "timed out"),
        (lambda r: httpx.Response(500, text="boom"), "HTTP 500"),
        (lambda r: httpx.Response(200, text="<html>"), "not JSON"),
        (lambda r: httpx.Response(200, json={"done": True}), "no message"),
    ],
)
def test_ollama_failures_raise_llm_error(handler, text):
    with pytest.raises(llm.LlmError, match=text):
        ollama(handler).chat([], [])


def test_check_available_reports_missing_model_and_down_server():
    def has_other(request):
        return httpx.Response(200, json={"models": [{"name": "other:1b"}]})

    with pytest.raises(llm.LlmError, match="not installed"):
        ollama(has_other).check_available()

    def down(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(llm.LlmError, match="not reachable"):
        ollama(down).check_available()

    def ok(request):
        return httpx.Response(200, json={"models": [{"name": llm.DEFAULT_MODEL}]})

    ollama(ok).check_available()


def test_cli_prints_error_and_exits_nonzero_when_ollama_is_down(monkeypatch, capsys):
    def down(self):
        raise llm.LlmError("Ollama is not reachable")

    monkeypatch.setattr(llm.OllamaClient, "check_available", down)
    monkeypatch.setattr(agent_run, "OllamaClient", llm.OllamaClient)
    code = agent_run.main(["A1", "--agent-kind", "llm", "--gateway", "http://gateway.test"])
    captured = capsys.readouterr()
    assert code == 1
    assert "Ollama is not reachable" in captured.err
    assert "model called" not in captured.out and "step 1" not in captured.out  # no fake steps


def test_cli_default_reviewer_for_llm_is_human(monkeypatch, capsys):
    monkeypatch.setattr(llm.OllamaClient, "check_available", lambda self: (_ for _ in ()).throw(llm.LlmError("x")))
    agent_run.main(["A1", "--agent-kind", "llm", "--gateway", "http://gateway.test"])
    assert "reviewer=human" in capsys.readouterr().out


# Pacing --------------------------------------------------------------------------------


def scripted_gateway():
    """Fake gateway for a scripted E1 run: both steps ALLOW and executed."""
    return FakeGateway(lambda b, n: decision(result={"ok": True}))


def test_step_delay_sleeps_after_each_step():
    gw = scripted_gateway()
    naps: list[float] = []
    e1 = find_scenario("E1", SCENARIOS)
    run_scenario(e1, GatewayMode.protected, "http://gateway.test", canaries=CANARIES,
                 http_client=gw.client(), step_delay=0.7, sleep=naps.append)
    assert naps == [0.7, 0.7]


def test_default_step_delay_is_zero_and_eval_never_uses_it():
    gw = scripted_gateway()
    naps: list[float] = []
    e1 = find_scenario("E1", SCENARIOS)
    run_scenario(e1, GatewayMode.protected, "http://gateway.test", canaries=CANARIES,
                 http_client=gw.client(), sleep=naps.append)
    assert naps == []
    assert "step_delay" not in open(agent_eval.__file__, encoding="utf-8").read()


def test_step_delay_is_not_applied_while_waiting_for_a_ticket():
    naps: list[float] = []
    gw = FakeGateway(lambda b, n: decision("REVIEW", "PENDING", ticket_id="t1"), ticket_states=("pending", "pending", "rejected"))
    a1 = find_scenario("A1", SCENARIOS)
    # Every step here gets a ticket; the polling uses poll_interval and must add no step_delay sleeps.
    run_scenario(a1, GatewayMode.protected, "http://gateway.test", canaries=CANARIES, http_client=gw.client(),
                 poll_interval=0.0, step_delay=0.4, sleep=naps.append)
    assert naps == [0.4, 0.4, 0.4]  # one per step, none extra for the two polls


# Eval --with-llm ------------------------------------------------------------------------


def test_observer_flag_is_sent_only_when_requested():
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"session_id": "s"})

    client = AgentClient("http://x", httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x"))
    client.create_session("A1", {}, GatewayMode.protected)
    client.create_session("A1", {}, GatewayMode.protected, observer=True)
    assert "observer" not in bodies[0] and bodies[1]["observer"] is True


def test_with_llm_eval_fails_loudly_when_ollama_is_missing(tmp_path, monkeypatch):
    def down(*_a, **_k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(agent_eval.httpx, "get", down)
    report = agent_eval.run_eval("llm-down", "http://gateway.test", tmp_path, with_llm=True, only=["E1"])
    assert report.status == "failed" and report.with_llm is True
    assert "Ollama is not available" in report.error
    assert report.metrics == []  # no column was invented


def test_with_llm_eval_sets_flag_label_and_observer(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(agent_eval, "ensure_llm_available", lambda *a, **k: None)
    original = agent_eval.run_scenario

    def spy(scenario, mode, gateway, **kwargs):
        seen.append((mode, kwargs["observer"]))
        return original(scenario, mode, gateway, **kwargs)

    monkeypatch.setattr(agent_eval, "run_scenario", spy)
    from agent.stub_gateway import start_in_thread

    handle = start_in_thread(port=8001)
    try:
        report = agent_eval.run_eval("llm-ok", "http://127.0.0.1:8001", tmp_path, with_llm=True, poll_interval=0.05, only=["E1"])
    finally:
        handle.stop()
    assert report.status == "complete" and report.with_llm is True
    assert all("may vary slightly" in s.detail for s in report.scenarios)
    assert (GatewayMode.protected, True) in seen and (GatewayMode.passthrough, False) in seen


def test_rules_only_eval_still_reports_with_llm_false(tmp_path):
    from agent.stub_gateway import start_in_thread

    handle = start_in_thread(port=8001)
    try:
        report = agent_eval.run_eval("rules", "http://127.0.0.1:8001", tmp_path, poll_interval=0.05, only=["E1"])
    finally:
        handle.stop()
    assert report.with_llm is False
    assert all("may vary" not in s.detail for s in report.scenarios)
