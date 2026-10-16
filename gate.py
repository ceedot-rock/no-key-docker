#!/usr/bin/env python3
"""
gate.py — the spend gate: verified identity + spend-scoped Warrant, deny by default.

One function, used by the FastMCP server and the demo agent alike:

    authorize_call(rider_token, warrant, cost_cents, now=None)
      -> {"ok": True, "rider": {...}, "warrant_body": {...}, "remaining_cents": int}
      -> {"ok": False, "stage": "identity"|"warrant", "code": ..., "detail": ...}

Order of checks: identity first (a forged identity must never reach
spend logic), then the Warrant. Mirrors the adapter spec:
  body.agent_id == verified rider agent_id,
  cost_cents <= body.max_cents,
  now < body.until.
"""

from __future__ import annotations

from typing import Any, Optional

from rider_verify import verify_rider_token
from warrant_lib import gate_check


def authorize_call(rider_token: Any, warrant: Any, cost_cents: int,
                   now: Optional[int] = None) -> dict:
    if not isinstance(rider_token, str) or not rider_token:
        return {"ok": False, "stage": "identity", "code": "IDENTITY_MISSING",
                "detail": "no rider token presented"}
    ident = verify_rider_token(rider_token, now)
    if not ident["ok"]:
        return {"ok": False, "stage": "identity", **{k: v for k, v in ident.items() if k != "ok"}}
    rider = ident["rider"]
    gate = gate_check(warrant, rider["agent_id"], cost_cents, now)
    if not gate["ok"]:
        return {"ok": False, "stage": "warrant", **{k: v for k, v in gate.items() if k != "ok"}}
    return {"ok": True, "rider": rider, "warrant_body": gate["body"],
            "remaining_cents": gate["remaining_cents"]}
