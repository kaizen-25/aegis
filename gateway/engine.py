"""Pure rule evaluation (Rulebook section 1, steps 3 to 6). No I/O and no side effects.

The engine never executes anything. It returns an Evaluation; the gateway core acts on it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from contracts.enums import Classification, Flag, Risk, RuleKind, ToolName, Verdict
from contracts.models import PolicyRule, SessionRecord
from gateway.policy import LoadedPolicy

# Built-in rule text, exactly as in docs/policy-rulebook.md section 2.
R_SCOPE = "R-SCOPE"
R_SCOPE_TEXT = "This action is outside the current task (possible injection)"
R_STRIKES = "R-STRIKES"
R_STRIKES_TEXT = "Repeated denied attempts; session on watch or frozen"
R_DEFAULT = "R-DEFAULT-NO-MATCH"
R_DEFAULT_TEXT = "No rule covers this action; a human must decide"
R_FAIL_CLOSED = "R-SYSTEM-FAIL-CLOSED"
R_FAIL_CLOSED_TEXT = "Aegis could not evaluate this safely, so it was blocked"

R_LLM = "R-LLM-OBSERVER"
R_LLM_TEXT = "The local AI observer raised a concern; a human must decide"

BUILTIN_RULES = [
    {"id": R_SCOPE, "kind": "built-in", "description": R_SCOPE_TEXT, "risk": "medium",
     "rationale": "A tool, path or recipient outside the task scope may be an injected request"},
    {"id": R_LLM, "kind": "built-in", "description": R_LLM_TEXT, "risk": "medium",
     "rationale": "The optional local model can raise a flag, never lower one"},
    {"id": R_DEFAULT, "kind": "default", "description": R_DEFAULT_TEXT, "risk": "medium",
     "rationale": "Silence in the rulebook is never a yes"},
    {"id": R_FAIL_CLOSED, "kind": "default", "description": R_FAIL_CLOSED_TEXT, "risk": "high",
     "rationale": "When Aegis breaks, it stays locked"},
]
BUILTIN_IDS = {R_SCOPE, R_DEFAULT, R_FAIL_CLOSED, R_LLM}

STRICTNESS = {Verdict.ALLOW: 0, Verdict.REVIEW: 1, Verdict.BLOCK: 2}
TAINT_ORDER = [Classification.public, Classification.internal, Classification.confidential,
               Classification.restricted]

# Actions that only read. On-watch sessions keep these; everything else needs REVIEW.
READ_TOOLS = {ToolName.file_read.value, ToolName.db_query.value}
REGISTERED_TOOLS = {t.value for t in ToolName}


def taint_rank(value: Classification | str) -> int:
    return TAINT_ORDER.index(Classification(value))


def max_taint(a: Classification, b: Classification | None) -> Classification:
    if b is None:
        return a
    return a if taint_rank(a) >= taint_rank(b) else b


def tighten(current: Verdict, proposed: Verdict | None) -> Verdict:
    """The only way an optional observer may change a verdict: ALLOW can become REVIEW.

    BLOCK and REVIEW are never loosened, and an observer asking for BLOCK is capped at REVIEW.
    """
    if proposed is None or current is not Verdict.ALLOW:
        return current
    return Verdict.REVIEW if proposed is not Verdict.ALLOW else current


@dataclass
class Facts:
    """What the gateway knows about the (already normalized) action."""

    tool: str
    classification: Classification | None = None
    path: str | None = None
    table: str | None = None
    recipient: str | None = None
    recipient_kind: str | None = None  # "internal" | "external"
    target_exists: bool | None = None
    content_match: bool = False


@dataclass
class RuleHit:
    rule_id: str
    verdict: Verdict
    risk: Risk
    description: str
    rationale: str
    order: int
    flags: set[Flag] = field(default_factory=set)
    builtin: bool = False


@dataclass
class Evaluation:
    verdict: Verdict
    hits: list[RuleHit]  # winner first
    flags: set[Flag]
    content_match: bool = False

    @property
    def winner(self) -> RuleHit:
        return self.hits[0]

    @property
    def matched_rules(self) -> list[str]:
        return [h.rule_id for h in self.hits]

    @property
    def review_rule_ids(self) -> set[str]:
        return {h.rule_id for h in self.hits if h.verdict is Verdict.REVIEW}

    @property
    def policy_block(self) -> bool:
        """True when a policy rule (not a built-in, not the frozen gate) gave the final BLOCK."""
        w = self.winner
        return self.verdict is Verdict.BLOCK and not w.builtin and w.rule_id != R_STRIKES


def _tools_of(match_tool) -> set[str] | None:
    if match_tool is None:
        return None
    items = match_tool if isinstance(match_tool, list) else [match_tool]
    return {t.value if isinstance(t, ToolName) else str(t) for t in items}


def _matches(rule: PolicyRule, facts: Facts) -> bool:
    m = rule.match
    if m.unregistered_tool is not None and (facts.tool not in REGISTERED_TOOLS) != m.unregistered_tool:
        return False
    tools = _tools_of(m.tool)
    if tools is not None and facts.tool not in tools:
        return False
    if m.classification is not None and facts.classification != m.classification:
        return False
    if m.path_glob is not None and (facts.path is None or not fnmatchcase(facts.path, m.path_glob.lower())):
        return False
    if m.recipient is not None and facts.recipient_kind != m.recipient:
        return False
    if m.table is not None:
        tables = m.table if isinstance(m.table, list) else [m.table]
        if facts.table is None or facts.table not in [t.lower() for t in tables]:
            return False
    if m.target_exists is not None and facts.target_exists != m.target_exists:
        return False
    return True


def _rule_verdict(rule: PolicyRule, session: SessionRecord, facts: Facts) -> tuple[Verdict | None, bool]:
    """Return (verdict, content_match_used). Verdict is None when `when` does not hold."""
    when = rule.when
    if when is not None:
        if when.taint_at_least is not None and taint_rank(session.taint) < taint_rank(when.taint_at_least):
            return None, False
        if when.taint_below is not None and taint_rank(session.taint) >= taint_rank(when.taint_below):
            return None, False
        if when.untrusted_seen is not None and session.untrusted_content_seen != when.untrusted_seen:
            return None, False
        if when.content_match is not None and when.no_content_match is not None:
            if facts.content_match:
                return when.content_match, True
            return when.no_content_match, False
    if rule.verdict is not None:
        return rule.verdict, False
    if rule.kind is RuleKind.prohibited:
        return Verdict.BLOCK, False
    if rule.kind is RuleKind.requires_approval:
        return Verdict.REVIEW, False
    return None, False  # unreachable: the loader rejects rules without a verdict


def scope_violation(session: SessionRecord, facts: Facts) -> bool:
    scope = session.scope
    if facts.tool not in {t.value for t in scope.allowed_tools}:
        return True
    # Paths apply to file.read only; recipients to email.send only (drafts are not checked).
    if facts.tool == ToolName.file_read.value:
        patterns = [p.lower().replace("\\", "/") for p in scope.allowed_paths]
        if facts.path is None or not any(fnmatchcase(facts.path, p) for p in patterns):
            return True
    if facts.tool == ToolName.email_send.value:
        patterns = [p.lower() for p in scope.allowed_recipients]
        if facts.recipient is None or not any(fnmatchcase(facts.recipient, p) for p in patterns):
            return True
    return False


def evaluate(loaded: LoadedPolicy, session: SessionRecord, facts: Facts) -> Evaluation:
    """Collect every matching rule and let the strictest verdict win."""
    policy = loaded.policy
    esc = loaded.escalation_rule
    s_id = esc.id if esc else R_STRIKES
    s_order = loaded.order[esc.id] if esc else len(policy.rules)
    s_risk = esc.risk if esc else Risk.high
    s_desc = esc.description if esc else R_STRIKES_TEXT
    s_why = esc.rationale if esc else ""

    # Step 3, session gate: a frozen session is blocked before anything else is looked at.
    if session.strikes >= loaded.freeze_at or session.state.value == "frozen":
        hit = RuleHit(s_id, Verdict.BLOCK, s_risk, s_desc, s_why, s_order)
        return Evaluation(Verdict.BLOCK, [hit], set())

    hits: list[RuleHit] = []
    flags: set[Flag] = set()
    content_match_used = False

    # Step 4, collect matches.
    for index, rule in enumerate(policy.rules):
        if rule.kind is RuleKind.escalation:
            continue
        if not _matches(rule, facts):
            continue
        verdict, used_match = _rule_verdict(rule, session, facts)
        if verdict is None:
            continue
        content_match_used = content_match_used or used_match
        hits.append(RuleHit(rule.id, verdict, rule.risk, rule.description, rule.rationale, index))
    if content_match_used:
        flags.add(Flag.CONTENT_MATCH)

    # Step 5, scope check (built-in, sorts after every policy rule).
    if scope_violation(session, facts):
        hits.append(RuleHit(R_SCOPE, Verdict.REVIEW, Risk.medium, R_SCOPE_TEXT,
                            "Outside the task scope", len(policy.rules), {Flag.OFF_TASK}, True))
        flags.add(Flag.OFF_TASK)

    # Step 3 (second half), applied at the end: an on-watch session reviews every non-read action.
    if session.strikes >= loaded.watch_at and facts.tool not in READ_TOOLS:
        hits.append(RuleHit(s_id, Verdict.REVIEW, s_risk, s_desc, s_why, s_order))

    # Step 6, combine. No match at all means REVIEW.
    if not hits:
        hits.append(RuleHit(R_DEFAULT, Verdict.REVIEW, Risk.medium, R_DEFAULT_TEXT,
                            "Silence in the rulebook is never a yes", len(policy.rules) + 1, set(), True))
    hits.sort(key=lambda h: (-STRICTNESS[h.verdict], h.order))
    return Evaluation(hits[0].verdict, hits, flags, content_match_used)
