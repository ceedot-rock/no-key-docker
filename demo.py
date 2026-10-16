#!/usr/bin/env python3
"""
demo.py — "the agent that spends money without holding keys."

A demo agent for the Collabnix $250 Agent Challenge (track: No Keys Allowed).
It makes paid API calls where every call is authorized by a signed Warrant
(spend mandate) and the agent authenticates with a verified Agent-Rider
identity. It NEVER holds a wallet private key or an API token for the paid
service — the Warrant IS the permission slip.

    python demo.py [--rider-token PATH] [--live-spend]

Identity: --rider-token PATH, or RIDER_TOKEN env, or mint one live with
          AGENT_RIDER_API_KEY env (POST /api/rider/issue). The key is read
          from the environment only — never stored in this repo.

Modes:
  default      dry-run: the x402 upstream is SIMULATED, a ledger records what
               WOULD have been spent. No money moves. Ever.
  --live-spend hits the real https://rider-x402.fly.dev endpoints. Unpaid
               calls return HTTP 402 with x402 payment terms, which the demo
               prints as proof the price is real — and then STOPS. Settlement
               needs a funded wallet and is the operator's explicit step,
               never the demo's.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time

# ---- args first: --live-spend must be known before server.py is imported ----
parser = argparse.ArgumentParser(description="Warrant-gated demo agent (dry-run by default)")
parser.add_argument("--rider-token", help="file containing an Agent-Rider JWT")
parser.add_argument("--live-spend", action="store_true",
                    help="hit the REAL x402 endpoints (still never settles payment)")
args = parser.parse_args()

if args.live_spend:
    os.environ["DRY_RUN"] = "0"   # server.py reads this at import time
    print("!! LIVE-SPEND mode: real x402 endpoints will be contacted.")
    print("!! The demo never settles payment: a 402 is printed, not paid.\n")
else:
    print("dry-run mode: upstream calls are SIMULATED, nothing is spent.\n")

import requests  # noqa: E402
from fastmcp import Client  # noqa: E402

import server  # noqa: E402  (reads DRY_RUN at import)
from warrant_lib import issue_warrant, attenuate  # noqa: E402

ISSUE_URL = "https://agentrider.fly.dev/api/rider/issue"


def _decode_payload(token: str) -> dict:
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def get_token() -> str:
    if args.rider_token:
        return open(args.rider_token).read().strip()
    if os.environ.get("RIDER_TOKEN"):
        return os.environ["RIDER_TOKEN"].strip()
    api_key = os.environ.get("AGENT_RIDER_API_KEY")
    if not api_key:
        sys.exit("no identity: pass --rider-token PATH, set RIDER_TOKEN, "
                 "or set AGENT_RIDER_API_KEY to mint one live")
    body = {}
    if os.environ.get("RIDER_AGENT_ID"):
        body["agent_id"] = os.environ["RIDER_AGENT_ID"]
    r = requests.post(ISSUE_URL, headers={"Authorization": f"Bearer {api_key}"},
                      json=body, timeout=30)
    r.raise_for_status()
    tok = r.json()["rider"]
    print(f"minted a fresh Rider JWT (jti={_decode_payload(tok).get('jti')})")
    return tok


def show(title: str, obj) -> None:
    print(f"\n--- {title} ---")
    print(json.dumps(obj, indent=1)[:1600])


def verdict(res: dict) -> str:
    if res.get("ok"):
        return "ALLOWED"
    return f"DENIED ({res.get('code')})"


async def call(client, tool: str, params: dict) -> dict:
    res = await client.call_tool(tool, params)
    if hasattr(res, "data") and res.data is not None:
        return res.data
    sc = getattr(res, "structured_content", None)
    if isinstance(sc, dict) and sc:
        return sc
    try:
        return json.loads(res.content[0].text)
    except Exception:
        return {"ok": False, "code": "DEMO_PARSE", "detail": str(res)[:200]}


async def main() -> None:
    token = get_token()
    agent_id = _decode_payload(token)["agent_id"]
    now = int(time.time())

    print("key inventory held by this agent:")
    print("  API keys for the paid service .... 0")
    print("  wallet private keys ............... 0")
    print("  short-lived identity JWT ......... 1 (Agent-Rider, 15-min TTL)")
    print("  spend permission slips ........... Warrants (attenuating)")

    warrant = issue_warrant({"agent_id": agent_id, "max_cents": 50, "until": now + 900})
    show("parent warrant (50c cap)", warrant)

    sample = base64.b64encode(b"the quick brown fox jumps over the lazy dog. " * 40).decode()

    async with Client(server.mcp) as client:
        # Scene 1: info, 2c — allowed
        r1 = await call(client, "info", {"rider_token": token, "warrant": warrant})
        show("1. info (2c) -> " + verdict(r1), r1)

        # Scene 2: compress, 25c — allowed
        r2 = await call(client, "compress",
                        {"rider_token": token, "warrant": warrant, "data_b64": sample})
        show("2. compress (25c) -> " + verdict(r2), r2)

        # Scene 3: attenuated 10c warrant, compress costs 25c — OVER_BUDGET
        small = attenuate(warrant, {"agent_id": agent_id, "max_cents": 10,
                                    "until": now + 900})
        r3 = await call(client, "compress",
                        {"rider_token": token, "warrant": small, "data_b64": sample})
        show("3. compress (25c) on a 10c warrant -> " + verdict(r3), r3)

        # Scene 4: expired warrant — WARRANT_EXPIRED
        dead = issue_warrant({"agent_id": agent_id, "max_cents": 50, "until": now - 5})
        r4 = await call(client, "info", {"rider_token": token, "warrant": dead})
        show("4. info on expired warrant -> " + verdict(r4), r4)

        # Scene 5: tampered identity — signature check fails before spend logic
        segs = token.split(".")
        tampered = segs[0] + "." + ("A" if segs[1][0] != "A" else "B") + segs[1][1:] + "." + segs[2]
        r5 = await call(client, "info", {"rider_token": tampered, "warrant": warrant})
        show("5. info with tampered JWT -> " + verdict(r5), r5)

        # Scene 6: delegation — parent 50c attenuates to sub-agent 10c
        r6 = await call(client, "delegate",
                        {"rider_token": token, "warrant": warrant,
                         "sub_agent_id": "demo-sub-01", "sub_max_cents": 10,
                         "sub_until": now + 600, "sub_task": "info"})
        show("6a. delegate info to sub-agent (10c cap) -> " + verdict(r6), r6)
        r7 = await call(client, "delegate",
                        {"rider_token": token, "warrant": warrant,
                         "sub_agent_id": "demo-sub-01", "sub_max_cents": 10,
                         "sub_until": now + 600, "sub_task": "compress"})
        show("6b. delegate compress to sub-agent (10c cap, costs 25c) -> " + verdict(r7), r7)

        # Ledger: what the agent spent (simulated unless --live-spend)
        r8 = await call(client, "my_ledger", {"rider_token": token})
        show("spend ledger for " + agent_id, r8)

    print("\nDone. No keys were held at any point. The Warrant was the permission slip.")


if __name__ == "__main__":
    asyncio.run(main())
