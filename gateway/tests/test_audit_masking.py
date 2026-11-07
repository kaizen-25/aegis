"""Hash chain, tamper detection, masking of canaries in every outward surface."""
import json
import sqlite3

import pytest

from contracts.enums import GatewayMode
from gateway.masking import Masker, mask_account, mask_email, mask_id, mask_phone
from gateway.seed import CANARIES, CUSTOMERS

from .conftest import Driver

RAW_CANARIES = [
    "meera.k.canary@examplemail.test", "98765 43210", "919876543210", "9876543210",
    "NC-CUST-7741", "ACC-0042-CANARY",
]


# ---------------------------------------------------------------- hash chain


def populate(gw, n=4):
    drv = Driver(gw)
    for _ in range(n):
        drv.do("file.read", {"path": "public/product_faq.md"})
    return drv


def test_chain_verifies_and_links(gw):
    populate(gw)
    rows = gw.audit.list()
    assert [r["seq"] for r in rows] == [1, 2, 3, 4]
    assert rows[0]["prev_hash"] == "0" * 64
    assert all(rows[i]["prev_hash"] == rows[i - 1]["hash"] for i in range(1, 4))
    assert gw.audit.verify() == (True, None)


def test_hash_definition(gw):
    import hashlib
    populate(gw, 1)
    row = gw.audit.list()[0]
    body = {k: v for k, v in row.items() if k not in ("hash", "llm_explanation")}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    assert row["hash"] == hashlib.sha256((row["prev_hash"] + canon).encode()).hexdigest()


@pytest.mark.parametrize("sql,broken", [
    ("UPDATE audit SET explanation='edited' WHERE seq=2", 2),
    ("UPDATE audit SET verdict='BLOCK' WHERE seq=3", 3),
    ("UPDATE audit SET args_masked='{}' WHERE seq=1", 1),
    ("UPDATE audit SET prev_hash='abc' WHERE seq=4", 4),
    ("UPDATE audit SET hash='deadbeef' WHERE seq=2", 2),
    ("DELETE FROM audit WHERE seq=2", 3),
])
def test_tamper_is_detected_at_the_right_row(gw, sql, broken):
    populate(gw)
    conn = sqlite3.connect(gw.audit.path)
    conn.execute(sql)
    conn.commit()
    conn.close()
    assert gw.audit.verify() == (False, broken)


def test_audit_survives_sandbox_reset_unless_cleared(gw):
    populate(gw, 2)
    gw.reset()
    assert len(gw.audit.list()) == 2 and gw.audit.verify()[0]
    gw.reset(clear_audit=True)
    assert gw.audit.list() == [] and gw.audit.executions() == []


def test_audit_filters(gw):
    drv = populate(gw, 2)
    drv.do("file.read", {"path": "restricted/api_keys.txt"})
    assert len(gw.audit.list(verdict="BLOCK")) == 1
    assert len(gw.audit.list(rule="R-PROHIBIT-RESTRICTED")) == 1
    assert len(gw.audit.list(tool="file.read", session_id=drv.sid)) == 3
    assert len(gw.audit.list(mode="passthrough")) == 0


def test_audit_record_has_every_contract_field(gw):
    populate(gw, 1)
    from contracts.models import AuditRecord
    AuditRecord.model_validate(gw.audit.list()[0])


# ---------------------------------------------------------------- masking formats


def test_mask_formats():
    assert mask_phone("+91 98765 43210") == "+91 ••••• ••210"
    assert mask_id("NC-CUST-7741") == "NC-CUST-••41"
    assert mask_account("ACC-0042-CANARY") == "ACC-••••-CANARY"
    assert mask_email("meera.k.canary@examplemail.test") == "me••••@examplemail.test"


def test_masker_masks_known_values_only():
    m = Masker.from_seed(CUSTOMERS, CANARIES)
    text = ("to vendor@partnerco.com about NC-CUST-7741 / nc-cust-7741, "
            "meera.k.canary@examplemail.test, +91 98765 43210, 919876543210, 98765-43210, ACC-0042-CANARY, "
            "unknown NC-CUST-9999 and +44 20 7946 0958")
    out = m.mask_text(text)
    assert "vendor@partnerco.com" in out
    assert "NC-CUST-9999" in out and "+44 20 7946 0958" in out
    for raw in RAW_CANARIES + ["nc-cust-7741", "98765-43210"]:
        assert raw not in out, raw
    assert "+91 ••••• ••210" in out
    assert "NC-CUST-••41" in out


def test_mask_walks_nested_structures():
    m = Masker.from_seed(CUSTOMERS, CANARIES)
    out = m.mask({"rows": [{"email": "arjun.malhotra@examplemail.test", "n": 3}], "t": ("NC-CUST-1002",)})
    assert "arjun.malhotra" not in json.dumps(out, ensure_ascii=False) and out["rows"][0]["n"] == 3


# ---------------------------------------------------------------- canaries never leak outward


def run_b1(client, mode):
    sid = client.post("/sessions", json={"scenario_id": "B1", "mode": mode}).json()["session_id"]

    def act(tool, args, step):
        return client.post("/actions/propose", json={"session_id": sid, "step": step, "tool": tool,
                                                      "args": args, "agent_kind": "scripted"}).json()
    act("file.read", {"path": "confidential/customers.csv"}, 1)
    act("db.query", {"table": "customers", "filter": {"customer_id": "nc-cust-7741"}}, 2)
    draft = act("email.draft", {"to": "vendor@partnerco.com", "subject": "meera.k.canary@examplemail.test",
                                "body": "Contact: +91 98765 43210, NC-CUST-7741, ACC-0042-CANARY"}, 3)
    send = act("email.send", {"draft_id": draft["result"]["draft_id"]}, 4)
    return sid, draft, send


@pytest.mark.parametrize("mode", ["protected", "passthrough"])
def test_canaries_never_appear_in_audit_events_outbox_or_responses(client, mode):
    gw = client.app.state.gateway
    sid, draft, send = run_b1(client, mode)
    surfaces = {
        "audit": json.dumps(client.get("/audit").json(), ensure_ascii=False),
        "events": "\n".join(data for _, data in gw.bus.history),
        "outbox": json.dumps(client.get("/outbox").json(), ensure_ascii=False),
        "draft": json.dumps(draft, ensure_ascii=False),
        "send": json.dumps(send, ensure_ascii=False),
        "session": json.dumps(client.get(f"/sessions/{sid}").json()),
    }
    for name, blob in surfaces.items():
        for raw in RAW_CANARIES:
            assert raw not in blob, f"{raw!r} leaked into {name}"
        assert "arjun.malhotra" not in blob, name
    assert "vendor@partnerco.com" in surfaces["audit"]
    assert "+91 ••••• ••210" in surfaces["audit"]
    assert "NC-CUST-••41" in surfaces["audit"]
    if mode == "passthrough":
        assert send["status"] == "EXECUTED" and "vendor@partnerco.com" in surfaces["outbox"]
        # the raw value exists only in the sandbox file itself
        raw_files = list((gw.sandbox / "outbox" / "passthrough").glob("*.json"))
        assert len(raw_files) == 1 and "98765 43210" in raw_files[0].read_text(encoding="utf-8")
    else:
        assert send["status"] == "BLOCKED" and client.get("/outbox").json() == []
        assert list((gw.sandbox / "outbox" / "protected").glob("*.json")) == []


def test_only_fingerprints_are_stored_for_sessions(client):
    gw = client.app.state.gateway
    sid, *_ = run_b1(client, "protected")
    conn = sqlite3.connect(gw.audit.path)
    stored = conn.execute("SELECT record FROM sessions WHERE session_id=?", (sid,)).fetchone()[0]
    for raw in RAW_CANARIES:
        assert raw not in stored
    assert json.loads(stored)["fingerprints"]
    exposed = client.get(f"/sessions/{sid}").json()
    assert exposed["fingerprints"] == []   # hashes are not exposed over the API either


def test_ticket_payloads_are_masked(client):
    gw = client.app.state.gateway
    sid = client.post("/sessions", json={"scenario_id": "C1"}).json()["session_id"]
    r = client.post("/actions/propose", json={
        "session_id": sid, "step": 1, "tool": "db.delete", "agent_kind": "scripted",
        "args": {"table": "customers", "record_id": "NC-CUST-7741"}}).json()
    ticket = client.get(f"/tickets/{r['ticket_id']}").json()
    blob = json.dumps(ticket, ensure_ascii=False)
    assert "NC-CUST-7741" not in blob and "NC-CUST-••41" in blob
    events = "\n".join(d for _, d in gw.bus.history)
    assert "NC-CUST-7741" not in events


def test_db_query_results_are_masked_in_response_and_audit(gw):
    drv = Driver(gw)
    d = drv.do("db.query", {"table": "customers", "filter": {}})
    blob = json.dumps(d.model_dump(mode="json"), ensure_ascii=False) + json.dumps(gw.audit.list(), ensure_ascii=False)
    assert d.result["count"] == 20
    for c in CUSTOMERS:
        assert c["email"] not in blob and c["customer_id"] not in blob


def test_secret_in_unvalidated_fields_is_masked_in_audit(gw):
    """A fail-closed record stores tool and session_id as given, so both must be masked first."""
    gw.propose({"session_id": "+91 98765 43210", "step": 1, "tool": "meera.k.canary@examplemail.test",
                     "args": {}, "agent_kind": "scripted"})
    stored = json.dumps(gw.audit.list(), default=str)
    assert "meera.k.canary@examplemail.test" not in stored
    assert "98765 43210" not in stored
