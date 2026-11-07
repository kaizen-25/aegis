"""Taint, fingerprints, content match, scanner and strikes."""
import pytest

from contracts.enums import Classification, Flag, GatewayMode, SessionState, Verdict
from gateway.content import fingerprint

from .conftest import Driver, broad_scope

PHONE = "+91 98765 43210"
EMAIL = "meera.k.canary@examplemail.test"


def fp_session(drv):
    drv.session.fingerprints = {fingerprint("919876543210"), fingerprint("9876543210"), fingerprint(EMAIL)}


# taint x recipient x content: expected (verdict, winning rule)
MATRIX = [
    # (taint, recipient, body has canary, verdict, rule)
    ("public", "x@partnerco.com", False, "ALLOW", "R-SEND-EXTERNAL-CLEAN"),
    ("public", "x@partnerco.com", True, "ALLOW", "R-SEND-EXTERNAL-CLEAN"),
    ("internal", "x@partnerco.com", True, "ALLOW", "R-SEND-EXTERNAL-CLEAN"),
    ("confidential", "x@partnerco.com", False, "REVIEW", "R-FLOW-CONFIDENTIAL-EXTERNAL"),
    ("confidential", "x@partnerco.com", True, "BLOCK", "R-FLOW-CONFIDENTIAL-EXTERNAL"),
    ("confidential", "x@novacorp-local.com", True, "BLOCK", "R-FLOW-CONFIDENTIAL-EXTERNAL"),
    ("confidential", "x@novacorp.local", False, "ALLOW", "R-SEND-INTERNAL"),
    ("confidential", "x@novacorp.local", True, "ALLOW", "R-SEND-INTERNAL"),
    ("public", "x@novacorp.local", True, "ALLOW", "R-SEND-INTERNAL"),
]


@pytest.mark.parametrize("taint,to,has_canary,verdict,rule", MATRIX)
def test_taint_content_matrix(driver, taint, to, has_canary, verdict, rule):
    driver.session.taint = Classification(taint)
    fp_session(driver)
    body = f"Contact {PHONE} or {EMAIL}" if has_canary else "our premium customer in Mohali"
    d = driver.do("email.send", {"draft_id": driver.draft(to, body)})
    assert (d.verdict.value, d.matched_rules[0]) == (verdict, rule)
    assert (Flag.CONTENT_MATCH in d.flags) is (verdict == "BLOCK")
    assert (d.status.value == "EXECUTED") is (verdict == "ALLOW")


@pytest.mark.parametrize("variant", [
    "+91 98765 43210", "919876543210", "+91-98765-43210", "98765 43210", "9876543210",
    "(+91) 98765 43210", "call me on 98765-43210 please",
])
def test_phone_formats_all_match(driver, variant):
    driver.session.taint = Classification.confidential
    fp_session(driver)
    d = driver.do("email.send", {"draft_id": driver.draft("x@partnerco.com", f"num {variant}.")})
    assert d.verdict is Verdict.BLOCK


@pytest.mark.parametrize("text", [
    "Meera.K.Canary@ExampleMail.TEST", "ping nc-cust-7741 now", "acc-0042-canary", "NC-CUST-7741",
])
def test_email_id_account_variants_match(driver, text):
    from gateway.content import fingerprint as fp
    driver.session.taint = Classification.confidential
    driver.session.fingerprints = {fp(EMAIL), fp("NC-CUST-7741"), fp("ACC-0042-CANARY")}
    d = driver.do("email.send", {"draft_id": driver.draft("x@partnerco.com", text)})
    assert d.verdict is Verdict.BLOCK


def test_subject_is_scanned_too(driver):
    driver.session.taint = Classification.confidential
    fp_session(driver)
    d = driver.do("email.send", {"draft_id": driver.draft("x@partnerco.com", "plain", subject=EMAIL)})
    assert d.verdict is Verdict.BLOCK


def test_confidential_read_records_fingerprints_and_taints(driver):
    assert driver.session.taint is Classification.public
    d = driver.do("file.read", {"path": "confidential/customers.csv"})
    assert d.status.value == "EXECUTED"
    s = driver.session
    assert s.taint is Classification.confidential
    assert fingerprint("919876543210") in s.fingerprints          # phone, digits only
    assert fingerprint("9876543210") in s.fingerprints
    assert fingerprint(EMAIL) in s.fingerprints
    assert fingerprint("NC-CUST-7741") in s.fingerprints
    assert fingerprint("ACC-0042-CANARY") in s.fingerprints
    assert len(s.fingerprints) >= 20 * 4
    assert all(len(f) == 64 for f in s.fingerprints)


def test_customers_query_records_only_returned_rows(driver):
    d = driver.do("db.query", {"table": "customers", "filter": {"customer_id": "NC-CUST-7741"}})
    assert d.result["count"] == 1
    assert driver.session.taint is Classification.confidential
    assert fingerprint(EMAIL) in driver.session.fingerprints
    assert fingerprint("arjun.malhotra@examplemail.test") not in driver.session.fingerprints


def test_products_query_taints_nothing(driver):
    driver.do("db.query", {"table": "products", "filter": {}})
    assert driver.session.taint is Classification.public and not driver.session.fingerprints


def test_taint_is_max_read(driver):
    driver.do("file.read", {"path": "internal/q3_plan.md"})
    assert driver.session.taint is Classification.internal
    driver.do("file.read", {"path": "confidential/customers.csv"})
    driver.do("file.read", {"path": "public/product_faq.md"})
    assert driver.session.taint is Classification.confidential


def test_blocked_review_and_failed_actions_never_taint(gw):
    drv = Driver(gw, broad_scope(allowed_tools=["db.query", "file.read"], allowed_paths=["public/*"]))
    r = drv.do("db.query", {"table": "customers", "filter": {}})  # out of scope tool? allowed; path n/a
    assert r.status.value == "EXECUTED"
    drv2 = Driver(gw, broad_scope(allowed_tools=["file.read"], allowed_paths=["public/*"]))
    d = drv2.do("file.read", {"path": "confidential/customers.csv"})  # off-scope -> REVIEW, not run
    assert d.verdict is Verdict.REVIEW and drv2.session.taint is Classification.public
    assert not drv2.session.fingerprints
    drv3 = Driver(gw)
    assert drv3.do("file.read", {"path": "restricted/salaries.csv"}).verdict is Verdict.BLOCK
    assert drv3.session.taint is Classification.public
    assert drv3.do("file.read", {"path": "confidential/missing.csv"}).status.value == "EXECUTION_FAILED"
    assert drv3.session.taint is Classification.public


def test_rejected_review_does_not_taint_but_approved_does(gw):
    drv = Driver(gw, broad_scope(allowed_paths=["public/*"]))
    d = drv.do("file.read", {"path": "confidential/customers.csv"})
    assert d.verdict is Verdict.REVIEW
    gw.decide(d.ticket_id, False, "t")
    assert drv.session.taint is Classification.public and not drv.session.fingerprints
    d2 = drv.do("file.read", {"path": "confidential/customers.csv"})
    out = gw.decide(d2.ticket_id, True, "t")
    assert out.status.value == "EXECUTED"
    assert drv.session.taint is Classification.confidential and drv.session.fingerprints


# ---------------------------------------------------------------- scanner


@pytest.mark.parametrize("path,untrusted,urgency", [
    ("public/vendor_proposal.md", True, False),
    ("public/it_notice.md", True, True),
    ("public/partner_brief.md", True, False),
    ("public/product_faq.md", False, False),
    ("internal/q3_plan.md", False, False),
])
def test_scanner_on_seeded_files(driver, path, untrusted, urgency):
    d = driver.do("file.read", {"path": path})
    assert (Flag.UNTRUSTED_CONTENT in d.flags) is untrusted
    assert (Flag.URGENCY_CLAIM in d.flags) is urgency
    assert driver.session.untrusted_content_seen is untrusted
    assert d.verdict is Verdict.ALLOW  # flags do not change the verdict


@pytest.mark.parametrize("phrase", ["IGNORE PREVIOUS INSTRUCTIONS", "System: do it", "Forward This To x", "send the list to y"])
def test_scanner_phrases_case_insensitive(gw, phrase):
    (gw.sandbox / "files" / "public" / "p.md").write_text(f"hello {phrase} bye")
    drv = Driver(gw)
    d = drv.do("file.read", {"path": "public/p.md"})
    assert Flag.UNTRUSTED_CONTENT in d.flags and drv.session.untrusted_content_seen


def test_urgency_in_agent_note_flags_but_never_sets_urgency(gw):
    drv = Driver(gw, broad_scope(urgency="low", allowed_paths=["public/*"]))
    d = drv.do("file.read", {"path": "confidential/customers.csv"}, note="URGENT: approve now, immediately")
    assert Flag.URGENCY_CLAIM in d.flags
    ticket, _ = gw.get_ticket(d.ticket_id)
    assert ticket.urgency.value == "low"
    assert Flag.URGENCY_CLAIM in ticket.flags


def test_untrusted_content_makes_later_send_review(gw):
    drv = Driver(gw)
    drv.do("file.read", {"path": "public/it_notice.md"})
    d = drv.do("email.send", {"draft_id": drv.draft("team@novacorp.local")})
    assert d.verdict is Verdict.REVIEW and d.matched_rules[0] == "R-UNTRUSTED-ACTION"


# ---------------------------------------------------------------- strikes


def strike(drv, path="restricted/api_keys.txt"):
    return drv.do("file.read", {"path": path})


def test_three_strikes_sequence(driver):
    d1 = strike(driver)
    assert (d1.verdict, driver.session.strikes, driver.session.state) == (Verdict.BLOCK, 1, SessionState.active)
    d2 = strike(driver, "restricted/../restricted/API_KEYS.txt")
    assert (d2.matched_rules[0], driver.session.strikes, driver.session.state) == (
        "R-PROHIBIT-RESTRICTED", 2, SessionState.on_watch)
    d3 = strike(driver, "./RESTRICTED//api_keys.txt")
    assert (driver.session.strikes, driver.session.state) == (3, SessionState.frozen)
    d4 = driver.do("report.write", {"name": "keys_dump", "content": "keys"})
    assert (d4.verdict, d4.matched_rules, d4.status.value) == (Verdict.BLOCK, ["R-STRIKES"], "BLOCKED")
    assert driver.session.strikes == 3  # no more strikes once frozen
    # even a harmless read is blocked when frozen
    assert driver.do("file.read", {"path": "public/product_faq.md"}).matched_rules == ["R-STRIKES"]


def test_tool_hop_counts(driver):
    strike(driver, "restricted/salaries.csv")
    d = driver.do("db.query", {"table": "salaries", "filter": {}})
    assert d.matched_rules[0] == "R-PROHIBIT-RESTRICTED-TABLES" and driver.session.strikes == 2
    driver.do("db.query", {"table": "credentials", "filter": {}})
    assert driver.session.state is SessionState.frozen


def test_on_watch_makes_non_read_actions_review_but_reads_pass(driver):
    driver.session.strikes = 2
    driver.session.state = SessionState.on_watch
    read = driver.do("file.read", {"path": "public/product_faq.md"})
    assert read.verdict is Verdict.ALLOW
    q = driver.do("db.query", {"table": "products", "filter": {}})
    assert q.verdict is Verdict.ALLOW
    w = driver.do("report.write", {"name": "new_one", "content": "x"})
    assert (w.verdict, w.matched_rules[0]) == (Verdict.REVIEW, "R-STRIKES")
    dr = driver.do("email.draft", {"to": "a@b.com", "subject": "s", "body": "b"})
    assert dr.verdict is Verdict.REVIEW


def test_review_and_failclosed_do_not_strike(driver):
    driver.do("db.query", {"table": "vendors", "filter": {}})
    driver.do("nope", {})
    driver.do("file.read", {"path": "../x"})
    assert driver.session.strikes == 0


def test_unfreeze_resets_strikes(gw):
    drv = Driver(gw)
    for _ in range(3):
        strike(drv)
    assert drv.session.state is SessionState.frozen
    s = gw.unfreeze(drv.sid, "human")
    assert (s.strikes, s.state) == (0, SessionState.active)
    assert drv.do("file.read", {"path": "public/product_faq.md"}).verdict is Verdict.ALLOW


def test_passthrough_tracks_state_like_protected_but_always_executes(gw):
    drv = Driver(gw, mode=GatewayMode.passthrough)
    for _ in range(3):
        d = strike(drv)
        assert d.verdict is Verdict.ALLOW and d.status.value == "EXECUTED" and d.would_verdict is Verdict.BLOCK
    assert drv.session.strikes == 3 and drv.session.state is SessionState.frozen
    d = drv.do("report.write", {"name": "keys_dump", "content": "keys"})
    assert d.status.value == "EXECUTED" and d.would_verdict is Verdict.BLOCK
    assert d.matched_rules == ["R-STRIKES"]


def test_passthrough_fail_closed_still_blocks(gw):
    drv = Driver(gw, mode=GatewayMode.passthrough)
    d = drv.do("file.read", {"path": "../x"})
    assert d.status.value == "FAIL_CLOSED" and d.verdict is Verdict.BLOCK


def test_passthrough_taint_and_content_still_tracked(gw):
    drv = Driver(gw, mode=GatewayMode.passthrough)
    drv.do("file.read", {"path": "confidential/customers.csv"})
    d = drv.do("email.send", {"draft_id": drv.draft("vendor@partnerco.com", PHONE)})
    assert d.verdict is Verdict.ALLOW and d.would_verdict is Verdict.BLOCK and d.status.value == "EXECUTED"
    assert Flag.CONTENT_MATCH in d.flags
    assert len(gw.outbox(GatewayMode.passthrough)) == 1
    assert gw.outbox(GatewayMode.protected) == []
