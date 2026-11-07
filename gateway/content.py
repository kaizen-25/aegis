"""Content analysis: untrusted-content scanner and sensitive-value fingerprints.

Fingerprints are SHA-256 hashes of normalized values. Raw values are never kept here.
"""
from __future__ import annotations

import csv
import hashlib
import io
import re
from typing import Any, Iterable

from gateway.normalize import normalize_id, normalize_phone

INJECTION_PHRASES = ("ignore previous instructions", "system:", "forward this to", "send the list to")
URGENCY_PHRASES = ("urgent", "immediately", "approve now")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d(?:[\s\-().]?\d){8,17}(?!\d)")
CUSTOMER_ID_RE = re.compile(r"\bNC-CUST-\d+\b", re.IGNORECASE)
ACCOUNT_RE = re.compile(r"\bACC-\d+-[A-Za-z0-9]+\b", re.IGNORECASE)

SENSITIVE_COLUMNS = {"email", "phone", "customer_id", "account"}


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def has_injection(text: str) -> bool:
    low = text.lower()
    return any(p in low for p in INJECTION_PHRASES)


def has_urgency(text: str) -> bool:
    low = text.lower()
    return any(p in low for p in URGENCY_PHRASES)


def _phone_variants(digits: str) -> set[str]:
    """A stored phone is kept both in full and as its last ten digits (no country code)."""
    out = {digits}
    if len(digits) > 10:
        out.add(digits[-10:])
    return out


def normalize_field(column: str, value: Any) -> set[str]:
    """Normalized forms of one sensitive column value, ready to hash."""
    if value is None:
        return set()
    text = str(value).strip()
    if not text:
        return set()
    column = column.lower()
    if column == "email":
        return {text.lower()}
    if column == "phone":
        digits = normalize_phone(text)
        return _phone_variants(digits) if len(digits) >= 8 else set()
    if column in ("customer_id", "account"):
        return {normalize_id(text)}
    return set()


def fingerprints_from_rows(rows: Iterable[dict[str, Any]], fields: Iterable[str]) -> set[str]:
    wanted = {f.lower() for f in fields} & SENSITIVE_COLUMNS
    out: set[str] = set()
    for row in rows:
        for column, value in row.items():
            if column.lower() in wanted:
                out.update(fingerprint(v) for v in normalize_field(column, value))
    return out


def scan_values(text: str, windows: bool = True) -> set[str]:
    """Find email, phone, customer id and account patterns in free text; return normalized forms.

    With `windows`, a phone match also yields every 10 to 13 digit window, so a number that is
    glued to other digits is still seen when comparing a draft against stored fingerprints.
    """
    found: set[str] = set()
    for m in EMAIL_RE.finditer(text):
        found.add(m.group(0).lower())
    for m in CUSTOMER_ID_RE.finditer(text):
        found.add(normalize_id(m.group(0)))
    for m in ACCOUNT_RE.finditer(text):
        found.add(normalize_id(m.group(0)))
    for m in PHONE_RE.finditer(text):
        digits = normalize_phone(m.group(0))
        if not windows:
            found.update(_phone_variants(digits) if len(digits) >= 10 else set())
            continue
        for length in range(10, 14):
            for start in range(0, len(digits) - length + 1):
                found.add(digits[start:start + length])
    return found


def fingerprints_from_text(text: str, fields: Iterable[str]) -> set[str]:
    """Fingerprints of sensitive values inside a confidential file.

    CSV files with sensitive column names are read by column. Any other text falls back to
    the pattern scan.
    """
    fields = list(fields)
    out: set[str] = set()
    try:
        rows = list(csv.DictReader(io.StringIO(text)))
        if rows and rows[0] and set(k.lower() for k in rows[0] if k) & SENSITIVE_COLUMNS:
            out |= fingerprints_from_rows(rows, fields)
            return out
    except csv.Error:
        pass
    if not {f.lower() for f in fields}:
        return out
    for value in scan_values(text, windows=False):
        out.add(fingerprint(value))
    return out


def content_matches(text: str, fingerprints: set[str]) -> bool:
    """True if any value found in `text` hashes to a stored fingerprint."""
    if not fingerprints:
        return False
    return any(fingerprint(v) in fingerprints for v in scan_values(text))
