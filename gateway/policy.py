"""Load and validate the policy file and the scenario files. Any failure stops startup."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from contracts.enums import RuleKind, Verdict
from contracts.models import PolicyFile, PolicyRule, Scenario, ScenarioSummary


class ConfigError(Exception):
    """The policy or a scenario file is invalid. The gateway refuses to start."""


@dataclass
class LoadedPolicy:
    raw_text: str
    policy: PolicyFile
    watch_at: int = 2
    freeze_at: int = 3
    escalation_rule: PolicyRule | None = None
    order: dict[str, int] = field(default_factory=dict)


def _check_rule_has_verdict(rule: PolicyRule) -> None:
    if rule.kind is RuleKind.escalation:
        if rule.when is None or rule.when.watch_at is None or rule.when.freeze_at is None:
            raise ConfigError(f"{rule.id}: escalation rules need when.watch_at and when.freeze_at")
        return
    has_flow_verdicts = rule.when is not None and (
        rule.when.content_match is not None or rule.when.no_content_match is not None
    )
    if rule.kind in (RuleKind.prohibited, RuleKind.requires_approval):
        return
    if rule.verdict is None and not has_flow_verdicts:
        raise ConfigError(f"{rule.id}: rule has no verdict")
    if has_flow_verdicts and (rule.when.content_match is None or rule.when.no_content_match is None):
        raise ConfigError(f"{rule.id}: content_match and no_content_match must be set together")


def load_policy(path: Path) -> LoadedPolicy:
    try:
        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        policy = PolicyFile.model_validate(data)
    except Exception as exc:  # noqa: BLE001 - any failure must stop startup
        raise ConfigError(f"policy file {path} is invalid: {exc}") from exc
    loaded = LoadedPolicy(raw_text=text, policy=policy)
    for index, rule in enumerate(policy.rules):
        _check_rule_has_verdict(rule)
        loaded.order[rule.id] = index
        if rule.kind is RuleKind.escalation:
            loaded.escalation_rule = rule
            loaded.watch_at = rule.when.watch_at  # type: ignore[union-attr]
            loaded.freeze_at = rule.when.freeze_at  # type: ignore[union-attr]
    if loaded.watch_at >= loaded.freeze_at:
        raise ConfigError("watch_at must be lower than freeze_at")
    return loaded


def load_scenarios(directory: Path) -> dict[str, Scenario]:
    """Load scenarios/[A-Z]*.yaml. Files starting with _ are not scenarios."""
    scenarios: dict[str, Scenario] = {}
    files = sorted(p for p in Path(directory).glob("*.yaml") if p.name[:1].isupper())
    for file in files:
        try:
            scenario = Scenario.model_validate(yaml.safe_load(file.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001
            raise ConfigError(f"scenario file {file.name} is invalid: {exc}") from exc
        if scenario.id in scenarios:
            raise ConfigError(f"duplicate scenario id {scenario.id}")
        scenarios[scenario.id] = scenario
    return scenarios


def short_id(scenario_id: str) -> str:
    return scenario_id.split("-", 1)[0]


def resolve_scenario_id(scenarios: dict[str, Scenario], given: str) -> str | None:
    """Accept a full id or a short prefix such as B1. Returns None if unknown or ambiguous."""
    if given in scenarios:
        return given
    needle = given.strip().lower()
    for sid in scenarios:
        if sid.lower() == needle:
            return sid
    by_short = [sid for sid in scenarios if short_id(sid).lower() == needle]
    if len(by_short) == 1:
        return by_short[0]
    by_prefix = [sid for sid in scenarios if sid.lower().startswith(needle)]
    if len(by_prefix) == 1:
        return by_prefix[0]
    return None


def summarize(scenario: Scenario) -> ScenarioSummary:
    scope = scenario.scope or scenario.sessions[0].scope  # type: ignore[index]
    return ScenarioSummary(
        id=scenario.id,
        short_id=short_id(scenario.id),
        title=scenario.title,
        category=scenario.category,
        brief_test=scenario.brief_test,
        task=scope.task,
        has_llm_prompt=bool(scenario.llm_prompt),
    )


__all__ = [
    "ConfigError",
    "LoadedPolicy",
    "Verdict",
    "load_policy",
    "load_scenarios",
    "resolve_scenario_id",
    "short_id",
    "summarize",
]
