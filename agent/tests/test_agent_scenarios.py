"""Loader, lookup and placeholder tests."""
from __future__ import annotations

import pytest

from agent.scenarios import (
    PlaceholderError,
    ResolveContext,
    ScenarioError,
    find_scenario,
    load_all,
    load_canaries,
    load_known_miss_notes,
    resolve,
    scenario_sessions,
)
from contracts.enums import ScenarioCategory


@pytest.fixture(scope="module")
def scenarios():
    return load_all()


def test_loads_twenty_scenarios_and_skips_underscore_files(scenarios):
    assert len(scenarios) == 20
    assert not any(s.id.startswith("_") for s in scenarios)
    counts = {}
    for s in scenarios:
        counts[s.category] = counts.get(s.category, 0) + 1
    assert counts[ScenarioCategory.benign] == 5
    assert counts[ScenarioCategory.known_miss] == 2
    assert counts[ScenarioCategory.timeout] == 1


def test_short_prefix_and_full_id(scenarios):
    assert find_scenario("B1", scenarios).id == "B1-exfil-exact"
    assert find_scenario("b1", scenarios).id == "B1-exfil-exact"
    assert find_scenario("E4-benign-tainted-internal", scenarios).id.startswith("E4")


def test_unknown_and_ambiguous(scenarios):
    with pytest.raises(ScenarioError):
        find_scenario("Z9", scenarios)
    with pytest.raises(ScenarioError, match="ambiguous"):
        find_scenario("E", scenarios)


def test_k2_has_two_sessions(scenarios):
    k2 = find_scenario("K2", scenarios)
    sessions = scenario_sessions(k2)
    assert len(sessions) == 2
    assert find_scenario("A1", scenarios).sessions is None
    assert len(scenario_sessions(find_scenario("A1", scenarios))) == 1


def test_invalid_file_is_rejected(tmp_path):
    (tmp_path / "bad.yaml").write_text("id: x\ntitle: y\n", encoding="utf-8")
    with pytest.raises(ScenarioError, match="bad.yaml"):
        load_all(tmp_path)


def test_underscore_files_not_loaded_as_scenarios(tmp_path):
    (tmp_path / "_note.yaml").write_text("not: a scenario\n", encoding="utf-8")
    assert load_all(tmp_path) == []


def test_canaries_load():
    canaries = load_canaries()
    assert {"email_1", "phone_1"} <= set(canaries)


def test_resolves_canary_in_nested_args(scenarios):
    b1 = find_scenario("B1", scenarios)
    ctx = ResolveContext(canaries=load_canaries())
    body = resolve(b1.steps[1].args, ctx)
    assert "{{" not in str(body)
    assert ctx.canaries["phone_1"] in body["body"]


def test_last_draft_and_last_result():
    ctx = ResolveContext(canaries={}, last_draft="draft-7", last_result={"a": {"b": 5}, "id": "x"})
    assert resolve({"draft_id": "{{last_draft}}"}, ctx) == {"draft_id": "draft-7"}
    assert resolve("{{last_result.id}}", ctx) == "x"
    assert resolve("{{last_result.a.b}}", ctx) == 5
    assert resolve("id={{last_result.id}}!", ctx) == "id=x!"


def test_missing_values_raise_when_strict():
    ctx = ResolveContext(canaries={"a": "1"})
    with pytest.raises(PlaceholderError):
        resolve("{{canary.nope}}", ctx)
    with pytest.raises(PlaceholderError):
        resolve("{{last_draft}}", ctx)
    with pytest.raises(PlaceholderError):
        resolve("{{bogus.x}}", ctx)


def test_missing_values_marked_when_not_strict():
    ctx = ResolveContext(canaries={})
    assert resolve("{{last_draft}}", ctx, strict=False) == "UNRESOLVED:last_draft"
    assert ctx.unresolved == ["last_draft"]


def test_known_miss_notes_from_catalogue():
    notes = load_known_miss_notes()
    assert set(notes) == {"K1", "K2"}
    assert "Destination trust levels" in notes["K1"][1]
    assert "Labels that follow data" in notes["K2"][1]
    assert notes["K1"][0] and notes["K2"][0]
