"""Normalization applied before any rule runs (invariant 9).

Paths: backslashes to /, collapse slashes, resolve . and .., lowercase. A path that escapes the
sandbox root, is absolute, contains a NUL byte or uses a Windows-only trick is a fail-closed error.
Emails are lowercased, phones keep digits only, identifiers are uppercased.
"""
from __future__ import annotations

import re
import unicodedata

from gateway.errors import FailClosed

_WIN_DRIVE = re.compile(r"^[a-z]:")
_BAD_SEGMENT_CHARS = set(':*?"<>|')
_WIN_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_REPORT_NAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9 _\-]*[a-z0-9_])?$")


def normalize_path(raw: str) -> str:
    """Return a lowercase, slash-separated path relative to the sandbox files root."""
    if not isinstance(raw, str):
        raise FailClosed("path must be a string")
    if "\x00" in raw:
        raise FailClosed("path contains a NUL byte")
    text = unicodedata.normalize("NFKC", raw).replace("\\", "/").lower().strip()
    if not text:
        raise FailClosed("empty path")
    if text.startswith("/") or _WIN_DRIVE.match(text):
        raise FailClosed("absolute paths are not allowed")
    parts: list[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not parts:
                raise FailClosed("path escapes the sandbox root")
            parts.pop()
            continue
        parts.append(segment)
    if not parts:
        raise FailClosed("path resolves to the sandbox root")
    for segment in parts:
        # Windows silently drops trailing dots and spaces, so "restricted./x" would reach
        # restricted/x while classifying as an unknown folder. Reject them outright.
        if segment != segment.rstrip(". ") or segment != segment.strip():
            raise FailClosed("path segment ends with a dot or space")
        if _BAD_SEGMENT_CHARS & set(segment):
            raise FailClosed("path contains a forbidden character")
        if segment.split(".")[0] in _WIN_RESERVED:
            raise FailClosed("path uses a reserved device name")
        if any(ord(ch) < 32 for ch in segment):
            raise FailClosed("path contains a control character")
    return "/".join(parts)


def normalize_email(raw: str) -> str:
    """Lowercase and validate a single address. Exactly one @ is allowed."""
    if not isinstance(raw, str):
        raise FailClosed("email address must be a string")
    text = unicodedata.normalize("NFKC", raw).strip().lower()
    if text.count("@") != 1 or not _EMAIL_RE.match(text) or len(text) > 254:
        raise FailClosed("invalid email address")
    if any(ord(ch) < 33 for ch in text):
        raise FailClosed("invalid email address")
    return text


def email_domain(address: str) -> str:
    return address.rsplit("@", 1)[1]


def normalize_phone(raw: str) -> str:
    return re.sub(r"\D", "", raw)


def normalize_id(raw: str) -> str:
    return raw.strip().upper()


def normalize_report_name(raw: str) -> str:
    """A report name is a bare file stem. Any separator is a fail-closed error."""
    if not isinstance(raw, str):
        raise FailClosed("report name must be a string")
    if "\x00" in raw or "/" in raw or "\\" in raw:
        raise FailClosed("report name must not contain a path separator")
    text = unicodedata.normalize("NFKC", raw).strip().lower()
    if text.endswith(".md"):
        text = text[:-3]
    if not _REPORT_NAME_RE.match(text) or len(text) > 80:
        raise FailClosed("invalid report name")
    return text


def classify_path(path: str) -> str | None:
    """Classification from the top-level folder only, never from the file name."""
    top = path.split("/", 1)[0]
    if top in ("public", "internal", "confidential", "restricted"):
        return top
    if top == "reports":
        return "internal"
    return None
