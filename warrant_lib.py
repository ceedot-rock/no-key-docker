#!/usr/bin/env python3
"""
warrant_lib.py — "narrow" spend Warrants, exact port of the Slid Phi Labs
reference implementation (ceedot-rock/Agent-Rider src/lib/narrow.ts).

A Warrant is a spend permission slip with Biscuit-style offline attenuation:
budgets may only shrink as authority delegates down a chain. It is NOT a
general action/resource policy language — spend only (max_cents + until).

Shape:
    {v: 1, kind: "spl-narrow",
     authority: {agent_id, max_cents, until},
     hops: [{agent_id, max_cents, until}, ...]}

Semantics (faithful to narrow.ts, including error strings):
- max_cents: number, finite, integer, >= 0            ("warrant_cents")
- until:     number, finite, integer, > 0 (unix sec)  ("warrant_until")
- agent_id:  non-empty string                        ("warrant_agent")
- attenuate: each hop's max_cents <= previous max_cents and
             each hop's until     <= previous until   (never widen)
- verify:    kind/v check, chain monotonicity, then
             now >= last.until -> "warrant_expired"
- enforce:   last-hop agent_id == caller agent_id AND
             cost_cents <= last-hop max_cents AND now < until.
             Deny by default on ANY failure.
"""

from __future__ import annotations

import math
import time
from typing import Any, Optional


class WarrantError(Exception):
    """Raised by issue/attenuate on malformed or widening warrants."""


def _int_cents(n: Any) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise WarrantError("warrant_cents")
    return n


def _int_until(n: Any) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise WarrantError("warrant_until")
    return n


def _body(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise WarrantError("warrant_agent")
    agent_id = raw.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise WarrantError("warrant_agent")
    return {
        "agent_id": agent_id,
        "max_cents": _int_cents(raw.get("max_cents")),
        "until": _int_until(raw.get("until")),
    }


def issue_warrant(authority: dict) -> dict:
    """Create a fresh warrant naming one agent and a spend cap."""
    return {"v": 1, "kind": "spl-narrow", "authority": _body(authority), "hops": []}


def _last(w: dict) -> dict:
    return w["hops"][-1] if w["hops"] else w["authority"]


def attenuate(w: dict, nxt: dict) -> dict:
    """
    Delegate: append a hop that may only narrow the budget.
    Raises WarrantError("warrant_widen_cents" | "warrant_widen_until" | "warrant_kind").
    """
    if not isinstance(w, dict) or w.get("kind") != "spl-narrow" or w.get("v") != 1:
        raise WarrantError("warrant_kind")
    hop = _body(nxt)
    prev = _last(w)
    if hop["max_cents"] > prev["max_cents"]:
        raise WarrantError("warrant_widen_cents")
    if hop["until"] > prev["until"]:
        raise WarrantError("warrant_widen_until")
    return {"v": 1, "kind": "spl-narrow", "authority": w["authority"],
            "hops": [*w["hops"], hop]}


def verify_warrant(w: Any, now: Optional[int] = None) -> dict:
    """
    Structural verification. Returns {"ok": True, "body": <effective last hop>}
    or {"ok": False, "error": <narrow.ts error string>}.
    """
    now = int(time.time()) if now is None else now
    try:
        if not isinstance(w, dict) or w.get("kind") != "spl-narrow" or w.get("v") != 1:
            return {"ok": False, "error": "warrant_kind"}
        chain = [_body(w.get("authority")), *[_body(h) for h in w.get("hops", [])]]
        for i in range(1, len(chain)):
            if chain[i]["max_cents"] > chain[i - 1]["max_cents"]:
                return {"ok": False, "error": "warrant_widen_cents"}
            if chain[i]["until"] > chain[i - 1]["until"]:
                return {"ok": False, "error": "warrant_widen_until"}
        cur = chain[-1]
        if now >= cur["until"]:
            return {"ok": False, "error": "warrant_expired"}
        return {"ok": True, "body": cur}
    except WarrantError as e:
        return {"ok": False, "error": str(e) or "warrant_invalid"}
    except Exception:
        return {"ok": False, "error": "warrant_invalid"}


def remaining_cents(w: dict) -> int:
    v = verify_warrant(w)
    return v["body"]["max_cents"] if v["ok"] else 0


def parse_warrant(raw: Any) -> Optional[dict]:
    """Lenient parse: None unless the shape is exactly a narrow warrant."""
    if not isinstance(raw, dict):
        return None
    if raw.get("kind") != "spl-narrow" or raw.get("v") != 1:
        return None
    if not isinstance(raw.get("authority"), dict) or not isinstance(raw.get("hops"), list):
        return None
    try:
        return {"v": 1, "kind": "spl-narrow",
                "authority": _body(raw["authority"]),
                "hops": [_body(h) for h in raw["hops"]]}
    except WarrantError:
        return None


# ---------------------------------------------------------------------------
# Spend-gate enforcement (mirrors credits.ts):
#   gate.body.agent_id === caller && cost_cents <= gate.body.max_cents && now < until
# ---------------------------------------------------------------------------

def gate_check(warrant: Any, caller_agent_id: str, cost_cents: int,
               now: Optional[int] = None) -> dict:
    """
    Full enforcement. Returns:
      {"ok": True, "body": {...}, "remaining_cents": int}
      {"ok": False, "code": "WARRANT_DENIED"|"WARRANT_EXPIRED"|"OVER_BUDGET"|"AGENT_MISMATCH",
       "detail": str}
    Deny by default on any failure.
    """
    if isinstance(cost_cents, bool) or not isinstance(cost_cents, int) or cost_cents < 0:
        return {"ok": False, "code": "WARRANT_DENIED", "detail": "invalid cost_cents"}
    v = verify_warrant(warrant, now)
    if not v["ok"]:
        code = "WARRANT_EXPIRED" if v["error"] == "warrant_expired" else "WARRANT_DENIED"
        return {"ok": False, "code": code, "detail": v["error"]}
    body = v["body"]
    if body["agent_id"] != caller_agent_id:
        return {"ok": False, "code": "AGENT_MISMATCH",
                "detail": f"warrant names {body['agent_id']!r}, caller is {caller_agent_id!r}"}
    if cost_cents > body["max_cents"]:
        return {"ok": False, "code": "OVER_BUDGET",
                "detail": f"cost {cost_cents}c exceeds warrant cap {body['max_cents']}c"}
    return {"ok": True, "body": body, "remaining_cents": body["max_cents"]}
