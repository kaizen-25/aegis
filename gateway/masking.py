"""Mask known sensitive values everywhere they could be shown: args, results, audit, SSE, outbox.

Masking is by known value (seeded customers plus the canaries), so an address that is not a
customer value, such as vendor@partnerco.com, stays visible.

Formats: phone "+91 ••••• ••210", ID "NC-CUST-••41", account "ACC-••••-CANARY",
email "me••••@examplemail.test".
"""
from __future__ import annotations

import re
from typing import Any

from gateway.content import ACCOUNT_RE, CUSTOMER_ID_RE, EMAIL_RE
from gateway.normalize import normalize_phone

DOT = "•"
_SEP = r"[\s\-().]*"


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:2]}{DOT * 4}@{domain}"


def mask_phone(value: str) -> str:
    """Keep a leading +CC and the last three digits; mask every other digit."""
    digits_total = sum(ch.isdigit() for ch in value)
    keep_first = 2 if value.lstrip().startswith("+") else 0
    out: list[str] = []
    seen = 0
    for ch in value:
        if ch.isdigit():
            seen += 1
            keep = seen <= keep_first or seen > digits_total - 3
            out.append(ch if keep else DOT)
        else:
            out.append(ch)
    return "".join(out)


def mask_id(value: str) -> str:
    """NC-CUST-7741 -> NC-CUST-••41."""
    m = re.match(r"^(.*?)(\d+)$", value)
    if not m:
        return value[:2] + DOT * 4
    prefix, digits = m.groups()
    keep = digits[-2:] if len(digits) > 2 else ""
    return prefix + DOT * (len(digits) - len(keep)) + keep


def mask_account(value: str) -> str:
    """ACC-0042-CANARY -> ACC-••••-CANARY."""
    return re.sub(r"\d", DOT, value)


class Masker:
    def __init__(self, emails=(), phones=(), ids=(), accounts=()):
        self.emails = {e.lower() for e in emails}
        self.ids = {i.upper() for i in ids}
        self.accounts = {a.upper() for a in accounts}
        digit_strings: set[str] = set()
        for phone in phones:
            digits = normalize_phone(phone)
            if len(digits) >= 8:
                digit_strings.add(digits)
                if len(digits) > 10:
                    digit_strings.add(digits[-10:])
        # Longest first, so "+91 98765 43210" is matched whole before its ten-digit tail.
        ordered = sorted(digit_strings, key=len, reverse=True)
        self._phone_re = None
        self.phones = digit_strings
        if ordered:
            alts = ["(?:\\+?" + _SEP.join(re.escape(d) for d in digits) + ")" for digits in ordered]
            self._phone_re = re.compile(r"(?<!\d)(?:" + "|".join(alts) + r")(?!\d)")

    @classmethod
    def from_seed(cls, customers: list[dict[str, str]], canaries: dict[str, str]) -> "Masker":
        emails = [c["email"] for c in customers] + [v for k, v in canaries.items() if k.startswith("email")]
        phones = [c["phone"] for c in customers] + [v for k, v in canaries.items() if k.startswith("phone")]
        ids = [c["customer_id"] for c in customers] + [v for k, v in canaries.items() if k.startswith("customer_id")]
        accounts = [c["account"] for c in customers] + [v for k, v in canaries.items() if k.startswith("account")]
        return cls(emails, phones, ids, accounts)

    def mask_text(self, text: str) -> str:
        if not text:
            return text
        text = EMAIL_RE.sub(lambda m: mask_email(m.group(0)) if m.group(0).lower() in self.emails else m.group(0), text)
        text = CUSTOMER_ID_RE.sub(lambda m: mask_id(m.group(0)) if m.group(0).upper() in self.ids else m.group(0), text)
        text = ACCOUNT_RE.sub(lambda m: mask_account(m.group(0)) if m.group(0).upper() in self.accounts else m.group(0), text)
        if self._phone_re is not None:
            text = self._phone_re.sub(lambda m: mask_phone(m.group(0)), text)
        return text

    def mask(self, value: Any) -> Any:
        """Mask strings inside nested dicts, lists and tuples. Other types pass through."""
        if isinstance(value, str):
            return self.mask_text(value)
        if isinstance(value, dict):
            return {k: self.mask(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.mask(v) for v in value]
        return value
