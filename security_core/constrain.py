"""Layer 3 - CONSTRAIN: capability metadata + typed extraction.

The security core ASSIGNS capabilities. It does not enforce them - it does not
control any sinks. The Jac orchestrator enforces them (services/policy.jac).

Typed extraction converts surviving prose into schema-validated facts
(prices, dates, figures). Values that do not match the schema are rejected.
Every typed value keeps provenance = UNTRUSTED_WEB.
"""

from __future__ import annotations

import re
from typing import Any

WEB_ALLOWED = ["SUMMARIZE", "DISPLAY"]
WEB_FORBIDDEN = ["SEND_DATA", "SEND_EMAIL", "PAYMENT", "CODE_EXECUTION",
                 "CREDENTIAL_ACCESS", "TOOL_CALL", "MODIFY_INTENT"]

_PRICE = re.compile(
    r"(?P<plan>\b[A-Z][A-Za-z+]{1,20}(?:\s[A-Z][A-Za-z+]{1,20})?\b)?[^$€£\n]{0,40}?"
    r"(?P<cur>[$€£])\s?(?P<amt>\d{1,5}(?:[.,]\d{1,2})?)"
    r"(?:\s?(?:/|per)\s?(?P<period>month|mo|year|yr|user|seat|user/month))?",
)
_CUR = {"$": "USD", "€": "EUR", "£": "GBP"}
_PERIOD = {"mo": "month", "month": "month", "yr": "year", "year": "year",
           "user": "user", "seat": "user", "user/month": "user/month"}
_YEAR = re.compile(r"\b(19|20)\d{2}\b")
_PCT = re.compile(r"(\d{1,3}(?:\.\d+)?)\s?%")


def assign_capabilities(decision: str, next_link_allowed: bool) -> dict[str, list[str]]:
    allowed = list(WEB_ALLOWED)
    if decision != "BLOCK" and next_link_allowed:
        # URLs derived from web content may be *proposed* to the agent's
        # FOLLOW_LINK tool; Jac still checks the URL against its own policy.
        allowed.append("FOLLOW_LINK")
    if decision == "BLOCK":
        allowed = []
    return {"allowed": allowed, "forbidden": list(WEB_FORBIDDEN), "trust": "UNTRUSTED_WEB"}


def validate_fact(fact: dict[str, Any]) -> bool:
    kind = fact.get("kind")
    if kind == "price":
        return (isinstance(fact.get("amount"), (int, float)) and 0 <= fact["amount"] < 100000
                and fact.get("currency") in ("USD", "EUR", "GBP")
                and (fact.get("period") in (None, "month", "year", "user", "user/month"))
                and (fact.get("plan") is None or (isinstance(fact["plan"], str) and len(fact["plan"]) <= 40
                                                  and " " not in fact["plan"].strip()[20:])))
    if kind == "percent":
        return isinstance(fact.get("value"), (int, float)) and 0 <= fact["value"] <= 100
    if kind == "year":
        return isinstance(fact.get("value"), int) and 1900 <= fact["value"] <= 2100
    return False


def extract_typed(texts: list[str], limit: int = 12) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for t in texts:
        for m in _PRICE.finditer(t):
            try:
                amt = float(m.group("amt").replace(",", "."))
            except ValueError:
                continue
            plan = (m.group("plan") or "").strip() or None
            fact = {"kind": "price", "plan": plan, "amount": amt,
                    "currency": _CUR.get(m.group("cur")), "period": _PERIOD.get((m.group("period") or "").lower()),
                    "provenance": "UNTRUSTED_WEB"}
            if validate_fact(fact):
                facts.append(fact)
        for m in _PCT.finditer(t):
            fact = {"kind": "percent", "value": float(m.group(1)), "provenance": "UNTRUSTED_WEB"}
            if validate_fact(fact):
                facts.append(fact)
        if len(facts) >= limit:
            break
    seen, out = set(), []
    for f in facts:
        key = tuple(sorted((k, str(v)) for k, v in f.items()))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out[:limit]
