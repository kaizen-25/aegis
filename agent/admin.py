"""Operator-side calls used by the evaluation runner. The agent module never imports this."""
from __future__ import annotations

import httpx


class AdminError(Exception):
    pass


def _check(response: httpx.Response, what: str) -> None:
    if response.status_code >= 300:
        raise AdminError(f"{what} failed: HTTP {response.status_code} {response.text[:200]}")


def reset_sandbox(client: httpx.Client) -> None:
    _check(client.post("/sandbox/reset"), "POST /sandbox/reset")


def fetch_execution_ids(client: httpx.Client) -> set[str]:
    """Action ids whose tool handler actually ran, from GET /audit/executions.

    Accepts a list of ids, a list of objects with `action_id`, or an object wrapping such a list.
    """
    response = client.get("/audit/executions")
    _check(response, "GET /audit/executions")
    body = response.json()
    if isinstance(body, dict):
        for key in ("executions", "items", "records"):
            if isinstance(body.get(key), list):
                body = body[key]
                break
    if not isinstance(body, list):
        raise AdminError("GET /audit/executions returned an unrecognised shape")
    ids: set[str] = set()
    for item in body:
        if isinstance(item, str):
            ids.add(item)
        elif isinstance(item, dict) and isinstance(item.get("action_id"), str):
            ids.add(item["action_id"])
        else:
            raise AdminError("GET /audit/executions item has no action_id")
    return ids
