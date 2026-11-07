"""Scenario loading, lookup and placeholder resolution.

Canary values come from scenarios/_canaries.yaml. This module never reads the
gateway's data folder, so the agent has no way to see real sample data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from contracts.models import Scenario, ScenarioStep, TaskScope

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = REPO_ROOT / "scenarios"
CATALOGUE_PATH = REPO_ROOT / "docs" / "scenario-catalogue.md"
CANARY_FILE = "_canaries.yaml"

_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_]\w*)(?:\.([\w.]+))?\s*\}\}")


class ScenarioError(Exception):
    """A scenario file or lookup is invalid."""


class PlaceholderError(ScenarioError):
    """A {{placeholder}} could not be resolved."""


def short_id(scenario_id: str) -> str:
    return scenario_id.split("-")[0]


def load_canaries(directory: Path | None = None) -> dict[str, str]:
    path = (directory or SCENARIO_DIR) / CANARY_FILE
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ScenarioError(f"cannot read canaries from {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScenarioError(f"{path} must be a mapping of name to value")
    return {str(k): str(v) for k, v in raw.items()}


def load_scenario(path: Path) -> Scenario:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return Scenario.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ScenarioError(f"invalid scenario file {path.name}: {exc}") from exc


def load_all(directory: Path | None = None) -> list[Scenario]:
    """Every scenario in the folder, sorted by id. Files starting with _ are skipped."""
    folder = directory or SCENARIO_DIR
    scenarios = [
        load_scenario(path)
        for path in sorted(folder.glob("*.yaml"))
        if not path.name.startswith("_")
    ]
    ids = [s.id for s in scenarios]
    if len(ids) != len(set(ids)):
        raise ScenarioError("duplicate scenario ids")
    return sorted(scenarios, key=lambda s: s.id)


def find_scenario(query: str, scenarios: list[Scenario]) -> Scenario:
    """Accept a full id (B1-exfil-exact) or a short prefix (B1), case-insensitive."""
    q = query.strip().lower()
    exact = [s for s in scenarios if s.id.lower() == q]
    if exact:
        return exact[0]
    by_short = [s for s in scenarios if short_id(s.id).lower() == q]
    if len(by_short) == 1:
        return by_short[0]
    by_prefix = [s for s in scenarios if s.id.lower().startswith(q)]
    if len(by_prefix) == 1:
        return by_prefix[0]
    if not by_short and not by_prefix:
        raise ScenarioError(f"no scenario matches '{query}'")
    options = ", ".join(s.id for s in (by_short or by_prefix))
    raise ScenarioError(f"'{query}' is ambiguous: {options}")


def scenario_sessions(scenario: Scenario) -> list[tuple[TaskScope, list[ScenarioStep]]]:
    """One (scope, steps) pair per session; single-session scenarios give one pair."""
    if scenario.sessions is not None:
        return [(s.scope, s.steps) for s in scenario.sessions]
    assert scenario.scope is not None and scenario.steps is not None
    return [(scenario.scope, scenario.steps)]


@dataclass
class ResolveContext:
    canaries: dict[str, str]
    last_draft: str | None = None
    last_result: dict[str, Any] | None = None
    unresolved: list[str] = field(default_factory=list)


def _lookup(path: str, data: Any) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(path)
    return current


def _value(name: str, rest: str | None, ctx: ResolveContext) -> Any:
    if name == "canary" and rest:
        if rest not in ctx.canaries:
            raise KeyError(f"canary.{rest}")
        return ctx.canaries[rest]
    if name == "last_draft" and rest is None:
        if ctx.last_draft is None:
            raise KeyError("last_draft")
        return ctx.last_draft
    if name == "last_result" and rest:
        if ctx.last_result is None:
            raise KeyError(f"last_result.{rest}")
        return _lookup(rest, ctx.last_result)
    raise PlaceholderError(f"unknown placeholder {{{{{name}{'.' + rest if rest else ''}}}}}")


def resolve(value: Any, ctx: ResolveContext, strict: bool = True) -> Any:
    """Replace placeholders in strings, dicts and lists.

    strict=True raises PlaceholderError on a value that is not available.
    strict=False leaves a visible UNRESOLVED:<name> marker and records the name in
    ctx.unresolved, so the runner can still send the step and let the gateway judge it.
    """
    if isinstance(value, dict):
        return {k: resolve(v, ctx, strict) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, ctx, strict) for v in value]
    if not isinstance(value, str):
        return value

    def substitute(match: re.Match[str]) -> Any:
        name, rest = match.group(1), match.group(2)
        try:
            return _value(name, rest, ctx)
        except KeyError as exc:
            label = str(exc.args[0])
            if strict:
                raise PlaceholderError(f"cannot resolve {{{{{label}}}}}") from exc
            ctx.unresolved.append(label)
            return f"UNRESOLVED:{label}"

    whole = _PLACEHOLDER.fullmatch(value.strip())
    if whole:
        return substitute(whole)
    return _PLACEHOLDER.sub(lambda m: str(substitute(m)), value)


def load_known_miss_notes(path: Path | None = None) -> dict[str, tuple[str, str]]:
    """Read 'why' and 'future fix' for each known miss from the catalogue table (section 4)."""
    catalogue = path or CATALOGUE_PATH
    try:
        text = catalogue.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScenarioError(f"cannot read catalogue {catalogue}: {exc}") from exc
    notes: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 5 and re.fullmatch(r"K\d+", cells[0]):
            notes[cells[0]] = (cells[3], cells[4])
    if not notes:
        raise ScenarioError(f"no known-miss rows found in {catalogue}")
    return notes
