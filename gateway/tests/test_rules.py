"""Every rule in the Rulebook, one by one, plus combination and ordering."""
import sqlite3

import pytest

from contracts.enums import Classification, Flag, SessionState, Verdict
from contracts.models import SessionRecord
from gateway import engine
from gateway.engine import Facts
from gateway.policy import load_policy

from .conftest import POLICY, Driver, broad_scope

CUSTOMERS = {"table": "customers", "filter": {}}


def rule_of(d):
    return d.matched_rules[0]


@pytest.mark.parametrize("tool,args,verdict,rule", [
    ("file.read", {"path": "public/product_faq.md"}, "ALLOW", "R-READ-PUBLIC"),
    ("file.read", {"path": "internal/q3_plan.md"}, "ALLOW", "R-READ-INTERNAL"),
    ("file.read", {"path": "reports/q3_board_report.md"}, "ALLOW", "R-READ-INTERNAL"),
    ("file.read", {"path": "confidential/customers.csv"}, "ALLOW", "R-READ-CONFIDENTIAL"),
    ("file.read", {"path": "restricted/api_keys.txt"}, "BLOCK", "R-PROHIBIT-RESTRICTED"),
    ("file.read", {"path": "misc/notes.txt"}, "REVIEW", "R-DEFAULT-NO-MATCH"),
    ("file.read", {"path": "unknownfolder/x.txt"}, "REVIEW", "R-DEFAULT-NO-MATCH"),
    ("db.query", {"table": "salaries", "filter": {}}, "BLOCK", "R-PROHIBIT-RESTRICTED-TABLES"),
    ("db.query", {"table": "credentials", "filter": {}}, "BLOCK", "R-PROHIBIT-RESTRICTED-TABLES"),
    ("db.delete", {"table": "salaries", "record_id": "E-01"}, "BLOCK", "R-PROHIBIT-RESTRICTED-TABLES"),
    ("db.delete", {"table": "credentials", "record_id": "x"}, "BLOCK", "R-PROHIBIT-RESTRICTED-TABLES"),
    ("db.query", CUSTOMERS, "ALLOW", "R-DB-QUERY-CUSTOMERS"),
    ("db.query", {"table": "products", "filter": {}}, "ALLOW", "R-DB-QUERY-PRODUCTS"),
    ("db.query", {"table": "vendors", "filter": {}}, "REVIEW", "R-DEFAULT-NO-MATCH"),
    ("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"}, "REVIEW", "R-APPROVE-DELETE"),
    ("db.delete", {"table": "products", "record_id": "P-100"}, "REVIEW", "R-APPROVE-DELETE"),
    ("report.write", {"name": "fresh_report", "content": "x"}, "ALLOW", "R-REPORT-NEW"),
    ("report.write", {"name": "q3_board_report", "content": "x"}, "REVIEW", "R-APPROVE-OVERWRITE"),
    ("report.write", {"name": "Q3_Board_Report.md", "content": "x"}, "REVIEW", "R-APPROVE-OVERWRITE"),
    ("email.draft", {"to": "anyone@evil.com", "subject": "s", "body": "b"}, "ALLOW", "R-DRAFT"),
])
def test_single_rule(driver, tool, args, verdict, rule):
    d = driver.do(tool, args)
    assert d.verdict.value == verdict
    assert rule_of(d) == rule


def test_send_internal_allowed_at_any_taint(driver):
    driver.session.taint = Classification.confidential
    draft = driver.draft("team@novacorp.local")
    d = driver.do("email.send", {"draft_id": draft})
    assert (d.verdict, rule_of(d), d.status.value) == (Verdict.ALLOW, "R-SEND-INTERNAL", "EXECUTED")


def test_send_external_clean(driver):
    driver.session.taint = Classification.internal
    d = driver.do("email.send", {"draft_id": driver.draft("partner@partnerco.com")})
    assert (d.verdict, rule_of(d)) == (Verdict.ALLOW, "R-SEND-EXTERNAL-CLEAN")


def test_send_external_tainted_without_match_is_review(driver):
    driver.session.taint = Classification.confidential
    d = driver.do("email.send", {"draft_id": driver.draft("partner@partnerco.com", "nothing secret")})
    assert (d.verdict, rule_of(d)) == (Verdict.REVIEW, "R-FLOW-CONFIDENTIAL-EXTERNAL")
    assert Flag.CONTENT_MATCH not in d.flags


def test_send_external_tainted_with_match_is_block(driver):
    from gateway.content import fingerprint
    driver.session.taint = Classification.confidential
    driver.session.fingerprints.add(fingerprint("919876543210"))
    d = driver.do("email.send", {"draft_id": driver.draft("partner@partnerco.com", "call +91 98765 43210")})
    assert (d.verdict, rule_of(d)) == (Verdict.BLOCK, "R-FLOW-CONFIDENTIAL-EXTERNAL")
    assert Flag.CONTENT_MATCH in d.flags


def test_untrusted_action_rule(driver):
    driver.session.untrusted_content_seen = True
    d = driver.do("email.send", {"draft_id": driver.draft("team@novacorp.local")})
    assert (d.verdict, rule_of(d)) == (Verdict.REVIEW, "R-UNTRUSTED-ACTION")
    d2 = driver.do("db.delete", {"table": "customers", "record_id": "NC-CUST-1002"})
    assert "R-UNTRUSTED-ACTION" in d2.matched_rules
    # report.write stays allowed so summaries still work
    d3 = driver.do("report.write", {"name": "summary_x", "content": "ok"})
    assert d3.verdict is Verdict.ALLOW


def test_scope_adds_review_and_off_task_flag(gw):
    drv = Driver(gw, broad_scope(allowed_tools=["file.read"], allowed_paths=["public/*"]))
    d = drv.do("db.query", CUSTOMERS)
    assert (d.verdict, rule_of(d)) == (Verdict.REVIEW, "R-SCOPE")
    assert Flag.OFF_TASK in d.flags
    assert d.explanation == "This action is outside the current task (possible injection)"
    assert d.matched_rules == ["R-SCOPE", "R-DB-QUERY-CUSTOMERS"]


def test_scope_paths_only_apply_to_file_read(gw):
    drv = Driver(gw, broad_scope(allowed_tools=["file.read", "report.write"], allowed_paths=["public/*"]))
    assert drv.do("report.write", {"name": "any_name", "content": "x"}).verdict is Verdict.ALLOW
    assert drv.do("file.read", {"path": "internal/q3_plan.md"}).matched_rules[0] == "R-SCOPE"
    # normalization happens before the scope check
    assert drv.do("file.read", {"path": "public/../internal/q3_plan.md"}).matched_rules[0] == "R-SCOPE"
    assert drv.do("file.read", {"path": "PUBLIC//product_faq.md"}).verdict is Verdict.ALLOW


def test_scope_recipient_checked_on_send_only(gw):
    drv = Driver(gw, broad_scope(allowed_recipients=["team@novacorp.local"]))
    # drafts are not checked
    draft = drv.draft("audit@novacorp-audit.com")
    assert drv.do("email.send", {"draft_id": draft}).matched_rules[0] in ("R-SEND-EXTERNAL-CLEAN", "R-SCOPE")
    d = drv.do("email.send", {"draft_id": drv.draft("other@novacorp.local")})
    assert d.verdict is Verdict.REVIEW and d.matched_rules[0] == "R-SCOPE"
    ok = drv.do("email.send", {"draft_id": drv.draft("Team@NovaCorp.local")})
    assert ok.verdict is Verdict.ALLOW


@pytest.mark.parametrize("address,internal", [
    ("a@novacorp.local", True),
    ("A@NOVACORP.LOCAL", True),
    ("a@lists.novacorp.local", True),
    ("a@novacorp-local.com", False),
    ("a@novacorp.local.evil.com", False),
    ("a@sub.novacorp.local", False),
    ("a@evilnovacorp.local", False),
    ("a@novacorp.local.", False),
    ("a@partnerco.com", False),
    ("a@novacorp-audit.com", False),
])
def test_internal_only_on_exact_domain_match(driver, address, internal):
    d = driver.do("email.send", {"draft_id": driver.draft(address)})
    assert ("R-SEND-INTERNAL" in d.matched_rules) is internal


@pytest.mark.parametrize("pattern,address,ok", [
    ("*@novacorp.local", "x@novacorp.local", True),
    ("*@novacorp.local", "x@sub.novacorp.local", False),
    ("*@novacorp.local", "x@novacorp-local.com", False),
    ("*@novacorp.local", "x@evil.com", False),
    ("*@lists.novacorp.local", "x@lists.novacorp.local", True),
])
def test_recipient_globs_do_not_match_lookalikes(gw, pattern, address, ok):
    drv = Driver(gw, broad_scope(allowed_recipients=[pattern]))
    d = drv.do("email.send", {"draft_id": drv.draft(address)})
    assert ("R-SCOPE" not in d.matched_rules) is ok


def test_no_match_gives_default(driver):
    d = driver.do("db.query", {"table": "vendors", "filter": {}})
    assert d.matched_rules == ["R-DEFAULT-NO-MATCH"]
    assert d.explanation == "No rule covers this action; a human must decide"
    assert d.status.value == "PENDING" and d.ticket_id


def test_tool_registry_rule_is_loaded_and_fires_for_unregistered_tool():
    loaded = load_policy(POLICY)
    assert "R-TOOL-REGISTRY" in loaded.order
    session = SessionRecord(session_id="s", scenario_id="x", mode="protected", scope=broad_scope())
    ev = engine.evaluate(loaded, session, Facts(tool="shell.exec"))
    assert ev.verdict is Verdict.BLOCK and ev.matched_rules[0] == "R-TOOL-REGISTRY"


def test_strictest_wins_and_ordering():
    loaded = load_policy(POLICY)
    session = SessionRecord(session_id="s", scenario_id="x", mode="protected",
                            scope=broad_scope(allowed_recipients=["nobody@x.com"]),
                            taint=Classification.confidential, untrusted_content_seen=True)
    facts = Facts(tool="email.send", recipient="a@partnerco.com", recipient_kind="external", content_match=False)
    ev = engine.evaluate(loaded, session, facts)
    # R-FLOW (REVIEW), R-UNTRUSTED-ACTION (REVIEW), R-SCOPE (REVIEW): policy order, R-SCOPE last
    assert ev.matched_rules == ["R-FLOW-CONFIDENTIAL-EXTERNAL", "R-UNTRUSTED-ACTION", "R-SCOPE"]
    facts.content_match = True
    ev = engine.evaluate(loaded, session, facts)
    assert ev.verdict is Verdict.BLOCK and ev.matched_rules[0] == "R-FLOW-CONFIDENTIAL-EXTERNAL"


def test_block_outranks_review_and_allow_in_matched_rules(gw):
    drv = Driver(gw, broad_scope(allowed_tools=["report.write"]))
    d = drv.do("file.read", {"path": "restricted/api_keys.txt"})
    assert d.matched_rules == ["R-PROHIBIT-RESTRICTED", "R-SCOPE"]


def test_observer_can_only_tighten():
    assert engine.tighten(Verdict.ALLOW, Verdict.REVIEW) is Verdict.REVIEW
    assert engine.tighten(Verdict.ALLOW, Verdict.BLOCK) is Verdict.REVIEW  # capped at REVIEW
    assert engine.tighten(Verdict.ALLOW, None) is Verdict.ALLOW
    assert engine.tighten(Verdict.ALLOW, Verdict.ALLOW) is Verdict.ALLOW
    for current in (Verdict.REVIEW, Verdict.BLOCK):
        for proposed in Verdict:
            assert engine.tighten(current, proposed) is current  # never loosened, never changed


def test_db_query_filters_are_parameterized_and_allowlisted(driver):
    inj = driver.do("db.query", {"table": "customers", "filter": {"plan": "x' OR '1'='1"}})
    assert inj.status.value == "EXECUTED" and inj.result["count"] == 0
    bad_col = driver.do("db.query", {"table": "customers", "filter": {'plan" OR 1=1 --': "x"}})
    assert bad_col.status.value == "EXECUTION_FAILED"
    bad_table = driver.do("db.query", {"table": "customers; DROP TABLE customers", "filter": {}})
    assert bad_table.status.value == "FAIL_CLOSED"
    ok = driver.do("db.query", {"table": "customers", "filter": {"customer_id": "nc-cust-1002"}})
    assert ok.result["count"] == 1


def test_db_delete_actually_deletes_only_after_approval(gw):
    drv = Driver(gw)
    d = drv.do("db.delete", {"table": "customers", "record_id": "nc-cust-1002"})
    assert d.verdict is Verdict.REVIEW
    db = gw.sandbox / "novacorp.db"
    count = lambda: sqlite3.connect(db).execute("SELECT COUNT(*) FROM customers WHERE customer_id='NC-CUST-1002'").fetchone()[0]
    assert count() == 1
    gw.decide(d.ticket_id, True, "tester")
    assert count() == 0


def test_tool_failure_is_execution_failed_not_blocked(driver):
    d = driver.do("file.read", {"path": "public/does_not_exist.md"})
    assert d.verdict is Verdict.ALLOW and d.status.value == "EXECUTION_FAILED" and d.error


def test_report_write_saves_under_reports(gw, driver):
    d = driver.do("report.write", {"name": "My Notes", "content": "hello"})
    assert d.status.value == "EXECUTED"
    assert (gw.sandbox / "files" / "reports" / "my notes.md").read_text() == "hello"
    assert driver.do("report.write", {"name": "my notes", "content": "again"}).verdict is Verdict.REVIEW


def test_report_name_with_separator_fails_closed(driver):
    for name in ("sub/report", "..\\x", "../x"):
        d = driver.do("report.write", {"name": name, "content": "x"})
        assert d.status.value == "FAIL_CLOSED"
    assert driver.session.strikes == 0


def test_session_gate_state_sanity(driver):
    assert driver.session.state is SessionState.active
