#!/usr/bin/env python3
"""
server.py — FastMCP server exposing spend-gated tools.

Every tool takes the caller's Agent-Rider JWT (`rider_token`) and a narrow
Warrant (`warrant`) as explicit params, verifies identity against the live
JWKS, enforces the spend cap, and only then acts. Deny by default.

Tools (costs mirror the live x402 price list):
  info(rider_token, warrant)                                  -> 2c
  compress(rider_token, warrant, data_b64)                    -> 25c
  decompress(rider_token, warrant, data_b64)                  -> 10c
  delegate(rider_token, warrant, sub_agent_id, sub_max_cents,
           sub_until, sub_task)                               -> 0c itself;
     attenuates the warrant to a strictly smaller sub-warrant and runs
     sub_task ("info"|"compress"|"decompress") under it.
  my_ledger(rider_token)                                      -> 0c; spend log
     for the caller's own agent_id only.

Upstream mode:
  DRY_RUN=1 (default): simulate the x402 endpoints, record a simulated ledger.
     No money moves. This is the hackathon demo mode.
  DRY_RUN=0: POST the real https://rider-x402.fly.dev endpoints. Unpaid calls
     return HTTP 402 with payment terms, which are surfaced verbatim as
     {"ok": False, "code": "PAYMENT_REQUIRED", "terms": ...}. The server never
     settles payment itself — no wallet, no keys. Settlement is the
     operator's step, which is the entire point of the demo.

Run standalone:  python server.py            (streamable HTTP, :8000)
Demo (in-process): python demo.py            (uses fastmcp.Client in-memory)
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any, Optional

import requests
from fastmcp import FastMCP

from gate import authorize_call
from warrant_lib import attenuate, gate_check, WarrantError

X402_BASE = "https://rider-x402.fly.dev"
DRY_RUN = os.environ.get("DRY_RUN", "1") != "0"

mcp = FastMCP("warrant-gate")

COSTS = {"info": 2, "compress": 25, "decompress": 10}

_ledger: list[dict] = []


def _log(agent_id: str, tool: str, cost_cents: int, mode: str, note: str = "",
         delegated_by: Optional[str] = None) -> None:
    _ledger.append({"at": int(time.time()), "agent_id": agent_id, "tool": tool,
                    "cost_cents": cost_cents, "mode": mode, "note": note,
                    "delegated_by": delegated_by})


def _deny(result: dict) -> dict:
    return {"ok": False, "code": result["code"], "detail": result.get("detail", ""),
            "stage": result.get("stage", "")}


def _upstream(path: str, payload: dict, agent_id: str, tool: str,
              cost_cents: int, delegated_by: Optional[str] = None) -> dict:
    """Call the real x402 endpoint, or simulate it in dry-run mode."""
    if DRY_RUN:
        _log(agent_id, tool, cost_cents, "dry-run", "simulated upstream",
             delegated_by=delegated_by)
        return {"ok": True, "mode": "dry-run", "upstream": path,
                "simulated": True, "echo_bytes": len(str(payload.get("data", "")))}
    try:
        r = requests.post(X402_BASE + path, json=payload, timeout=30)
    except requests.RequestException as e:
        return {"ok": False, "code": "UPSTREAM_UNREACHABLE", "detail": str(e)}
    if r.status_code == 402:
        _log(agent_id, tool, 0, "live", "402 payment required, not settled",
             delegated_by=delegated_by)
        try:
            terms = r.json()
        except ValueError:
            terms = {"raw": r.text[:500]}
        return {"ok": False, "code": "PAYMENT_REQUIRED",
                "detail": "x402 terms issued; server holds no wallet and settles nothing",
                "terms": terms}
    _log(agent_id, tool, cost_cents, "live", f"upstream HTTP {r.status_code}",
         delegated_by=delegated_by)
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:2000]}
    return {"ok": r.ok, "mode": "live", "upstream": path,
            "http_status": r.status_code, "result": body}


def _gated(rider_token: Any, warrant: Any, tool: str) -> dict:
    """Run the gate; return (allowed, auth-or-denial)."""
    auth = authorize_call(rider_token, warrant, COSTS[tool])
    if not auth["ok"]:
        return {"allowed": False, "denial": _deny(auth)}
    return {"allowed": True, "auth": auth}


@mcp.tool()
def info(rider_token: str, warrant: dict) -> dict:
    """Service info (2c). Identity + spend verified before anything happens."""
    g = _gated(rider_token, warrant, "info")
    if not g["allowed"]:
        return g["denial"]
    out = _upstream("/api/x402/pcc/info", {}, g["auth"]["rider"]["agent_id"],
                    "info", COSTS["info"])
    out["warrant_cap_cents"] = g["auth"]["warrant_body"]["max_cents"]
    return out


@mcp.tool()
def compress(rider_token: str, warrant: dict, data_b64: str) -> dict:
    """Compress bytes (25c). data_b64: base64 of the input."""
    g = _gated(rider_token, warrant, "compress")
    if not g["allowed"]:
        return g["denial"]
    try:
        raw = base64.b64decode(data_b64)
    except Exception:
        return {"ok": False, "code": "BAD_INPUT", "detail": "data_b64 is not valid base64"}
    out = _upstream("/api/x402/pcc/compress", {"data": data_b64},
                    g["auth"]["rider"]["agent_id"], "compress", COSTS["compress"])
    out["input_bytes"] = len(raw)
    out["warrant_cap_cents"] = g["auth"]["warrant_body"]["max_cents"]
    return out


@mcp.tool()
def decompress(rider_token: str, warrant: dict, data_b64: str) -> dict:
    """Decompress bytes (10c). data_b64: base64 of the input."""
    g = _gated(rider_token, warrant, "decompress")
    if not g["allowed"]:
        return g["denial"]
    try:
        raw = base64.b64decode(data_b64)
    except Exception:
        return {"ok": False, "code": "BAD_INPUT", "detail": "data_b64 is not valid base64"}
    out = _upstream("/api/x402/pcc/decompress", {"data": data_b64},
                    g["auth"]["rider"]["agent_id"], "decompress", COSTS["decompress"])
    out["input_bytes"] = len(raw)
    out["warrant_cap_cents"] = g["auth"]["warrant_body"]["max_cents"]
    return out


@mcp.tool()
def delegate(rider_token: str, warrant: dict, sub_agent_id: str,
             sub_max_cents: int, sub_until: int, sub_task: str) -> dict:
    """
    Delegate a sub-task under an attenuated warrant (0c for the delegation
    itself; the sub-task spends against the SMALLER sub-cap).
    sub_task: "info" | "compress" | "decompress".
    """
    if sub_task not in COSTS:
        return {"ok": False, "code": "BAD_INPUT",
                "detail": f"sub_task must be one of {sorted(COSTS)}"}
    # Parent must hold a valid warrant naming the caller; delegation costs 0.
    auth = authorize_call(rider_token, warrant, 0)
    if not auth["ok"]:
        return _deny(auth)
    try:
        sub_warrant = attenuate(warrant, {"agent_id": sub_agent_id,
                                          "max_cents": sub_max_cents,
                                          "until": sub_until})
    except WarrantError as e:
        return {"ok": False, "code": "WARRANT_DENIED",
                "detail": f"attenuation refused: {e}"}
    # The server executes the sub-task on the parent's verified authority,
    # enforcing the SMALLER sub-cap against the named sub-agent holder.
    # (A real sub-agent calling back would present its own Rider JWT with
    # this sub-warrant; the cap it faces is identical.)
    sub = gate_check(sub_warrant, sub_agent_id, COSTS[sub_task])
    if not sub["ok"]:
        return {"ok": False, "code": "SUB_" + sub["code"],
                "detail": "sub-warrant denied: " + sub.get("detail", ""),
                "sub_warrant": sub_warrant}
    out = _upstream(f"/api/x402/pcc/{sub_task}",
                    {} if sub_task == "info" else {"data": ""},
                    sub_agent_id, f"delegate:{sub_task}", COSTS[sub_task],
                    delegated_by=auth["rider"]["agent_id"])
    out["sub_warrant"] = sub_warrant
    out["sub_cap_cents"] = sub["body"]["max_cents"]
    return out


@mcp.tool()
def my_ledger(rider_token: str) -> dict:
    """Spend log for the caller's own agent_id (0c)."""
    from rider_verify import verify_rider_token
    ident = verify_rider_token(rider_token)
    if not ident["ok"]:
        return _deny({"code": ident["code"], "detail": ident.get("detail", ""),
                      "stage": "identity"})
    aid = ident["rider"]["agent_id"]
    # Your spend plus everything you delegated down-chain: the budget tree.
    mine = [e for e in _ledger
            if e["agent_id"] == aid or e.get("delegated_by") == aid]
    return {"ok": True, "agent_id": aid, "entries": mine,
            "total_cents": sum(e["cost_cents"] for e in mine)}


if __name__ == "__main__":
    # Standalone: streamable HTTP for the sbx sandbox deployment.
    mcp.run(transport="http", host="0.0.0.0", port=8000)
