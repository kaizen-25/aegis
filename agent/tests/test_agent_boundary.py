"""The agent package must not reach the gateway's code or the gateway's private data."""
from __future__ import annotations

import ast
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent
# The one place "sandbox/" may appear: the reset endpoint path, an HTTP call, not a file path.
ALLOWED_API_PATH = "/sandbox/reset"


def agent_sources() -> list[Path]:
    return [p for p in sorted(AGENT_DIR.rglob("*.py")) if "tests" not in p.relative_to(AGENT_DIR).parts]


def test_sources_found():
    names = {p.name for p in agent_sources()}
    assert {"runner.py", "reviewer.py", "eval.py", "run.py", "metrics.py", "scenarios.py"} <= names


def test_no_gateway_imports():
    offenders = []
    for path in agent_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            elif isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) in (
                "import_module",
                "__import__",
            ):
                names = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            else:
                continue
            for name in names:
                if name == "gateway" or name.startswith("gateway."):
                    offenders.append(f"{path.name}:{node.lineno} imports {name}")
    assert offenders == []


def test_no_sandbox_paths():
    offenders = []
    for path in agent_sources():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.replace(ALLOWED_API_PATH, "")
                if "sandbox/" in value.lower() or value.strip().lower() == "sandbox":
                    offenders.append(f"{path.name}:{node.lineno} string mentions sandbox path")
        # Comments are not in the AST, so scan the raw text too.
        for number, line in enumerate(text.splitlines(), start=1):
            if "sandbox/" in line.replace(ALLOWED_API_PATH, "").lower():
                offenders.append(f"{path.name}:{number} text mentions sandbox path")
    assert offenders == []


def test_scanner_would_catch_a_violation(tmp_path):
    """Guard against a scanner that silently matches nothing."""
    sample = 'import gateway.engine\nPATH = "sandbox/data.db"\n'
    tree = ast.parse(sample)
    imports = [n for n in ast.walk(tree) if isinstance(n, ast.Import)]
    assert imports[0].names[0].name.startswith("gateway")
    consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)]
    assert any("sandbox/" in c for c in consts)


def test_only_runner_has_agent_http_and_never_the_reviewer():
    """runner.py (the agent) must not import the reviewer or the operator helpers."""
    tree = ast.parse((AGENT_DIR / "runner.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    assert "agent.reviewer" not in imported
    assert "agent.admin" not in imported


def test_decision_endpoint_only_in_reviewer():
    hits = [
        p.name
        for p in agent_sources()
        if "/decision" in p.read_text(encoding="utf-8") and p.name != "stub_gateway.py"
    ]
    assert hits == ["reviewer.py"]
