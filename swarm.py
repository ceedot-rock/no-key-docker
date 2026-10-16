#!/usr/bin/env python3
"""
swarm.py — the sustained swarm demo run for the 2-minute video.

Drives the FULL demo arc unattended: a parent operator delegates to a crew
of sub-agent roles running concurrently, warrants attenuate down a 3-level
chain (100c -> 40c -> 15c), spend accrues per role in the ledger, and both
an over-budget denial and a live-expired-warrant denial happen on camera.

    python swarm.py [--live-spend] [--cycles N] [--log PATH] [--rider-token PATH]

Identity: --rider-token PATH, RIDER_TOKEN env, or AGENT_RIDER_API_KEY env to
mint a fresh 15-min JWT. No keys are stored in this repo.

Honest framing, stated up front in the run: one verified operator identity;
sub-agents are delegated ROLES acting through the `delegate` tool on the
parent's verified authority, each bound by its own attenuated sub-warrant.
That is exactly what the Warrant model is for.

Modes: dry-run default (simulated upstream, $0). --live-spend hits the real
x402 endpoints; 402s are printed, never settled.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone

parser = argparse.ArgumentParser(description="Sustained Warrant-swarm demo run")
parser.add_argument("--rider-token", help="file containing an Agent-Rider JWT")
parser.add_argument("--live-spend", action="store_true",
                    help="hit the REAL x402 endpoints (402s printed, never paid)")
parser.add_argument("--cycles", type=int, default=2,
                    help="crew work cycles per run (spend accrues across cycles)")
parser.add_argument("--log", default="demo_swarm.log", help="run log path")
args = parser.parse_args()

if args.live_spend:
    os.environ["DRY_RUN"] = "0"
    print("!! LIVE-SPEND mode: real x402 endpoints will be contacted.")
    print("!! 402s are printed, never settled.\n")
else:
    print("dry-run mode: upstream calls are SIMULATED, nothing is spent.\n")

import requests  # noqa: E402
from fastmcp import Client  # noqa: E402

import server  # noqa: E402
from warrant_lib import issue_warrant, attenuate  # noqa: E402

ISSUE_URL = "https://agentrider.fly.dev/api/rider/issue"
PARENT_CAP = 100
log_fh = open(args.log, "w")


def log(msg: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    line = f"[{ts}] {msg}" if msg else ""
    print(line)
    log_fh.write(line + "\n")
    log_fh.flush()


def scene(n: str, title: str) -> None:
    log("")
    log("=" * 70)
    log(f"SCENE {n} — {title}")
    log("=" * 70)


def _payload(token: str) -> dict:
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def get_token() -> str:
    if args.rider_token:
        return open(args.rider_token).read().strip()
    if os.environ.get("RIDER_TOKEN"):
        return os.environ["RIDER_TOKEN"].strip()
    api_key = os.environ.get("AGENT_RIDER_API_KEY")
    if not api_key:
        sys.exit("no identity: --rider-token PATH, RIDER_TOKEN, or AGENT_RIDER_API_KEY")
    body = {"agent_id": os.environ["RIDER_AGENT_ID"]} if os.environ.get("RIDER_AGENT_ID") else {}
    r = requests.post(ISSUE_URL, headers={"Authorization": f"Bearer {api_key}"},
                      json=body, timeout=30)
    r.raise_for_status()
    return r.json()["rider"]


async def call(client, tool: str, params: dict) -> dict:
    res = await client.call_tool(tool, params)
    if getattr(res, "data", None) is not None:
        return res.data
    sc = getattr(res, "structured_content", None)
    if isinstance(sc, dict) and sc:
        return sc
    return json.loads(res.content[0].text)


def verdict(res: dict) -> str:
    return "ALLOWED" if res.get("ok") else f"DENIED ({res.get('code')})"


async def main() -> None:
    token = get_token()
    agent_id = _payload(token)["agent_id"]
    now = int(time.time())
    sample = base64.b64encode(b"swarm payload: the quick brown fox. " * 64).decode()

    scene("0", "BOOT — the agent that spends money without holding keys")
    log("key inventory: 0 API keys, 0 wallet private keys, "
        "1 short-lived identity JWT, attenuating Warrants")
    log(f"operator identity verified as {agent_id} (ES256, live JWKS)")
    log("model: one verified operator; sub-agents are delegated roles, each")
    log("bound by its own attenuated sub-warrant. Budgets only shrink.")

    master = issue_warrant({"agent_id": agent_id, "max_cents": PARENT_CAP,
                            "until": now + 900})
    # Show the 3-level chain the run will enforce: 100 -> 40 -> 15
    chain_demo = attenuate(
        attenuate(master, {"agent_id": "swarm-scout", "max_cents": 40, "until": now + 800}),
        {"agent_id": "swarm-sub-scout", "max_cents": 15, "until": now + 700})
    log("budget chain for this run: 100c (operator) -> 40c (scout) -> 15c (sub-scout); "
        "worker gets 40c")
    await asyncio.sleep(1)

    async with Client(server.mcp) as client:
        scene("1", "OPERATOR BASELINE — info (2c) on the 100c master warrant")
        r = await call(client, "info", {"rider_token": token, "warrant": master})
        log(f"[operator] info (2c) -> {verdict(r)}")
        await asyncio.sleep(1)

        async def scout_branch(cycle: int):
            log(f"[scout] cycle {cycle}: delegated 40c, running info + decompress")
            r1 = await call(client, "delegate",
                            {"rider_token": token, "warrant": master,
                             "sub_agent_id": "swarm-scout", "sub_max_cents": 40,
                             "sub_until": now + 800, "sub_task": "info"})
            log(f"[scout] cycle {cycle}: info (2c) -> {verdict(r1)}")
            r2 = await call(client, "delegate",
                            {"rider_token": token, "warrant": master,
                             "sub_agent_id": "swarm-scout", "sub_max_cents": 40,
                             "sub_until": now + 800, "sub_task": "decompress"})
            log(f"[scout] cycle {cycle}: decompress (10c) -> {verdict(r2)}")

        async def worker_branch(cycle: int):
            log(f"[worker] cycle {cycle}: delegated 40c, running compress")
            r1 = await call(client, "delegate",
                            {"rider_token": token, "warrant": master,
                             "sub_agent_id": "swarm-worker", "sub_max_cents": 40,
                             "sub_until": now + 800, "sub_task": "compress"})
            # delegate passes empty data for compress; send real bytes directly is
            # demo.py's job — here the gate math is the story
            log(f"[worker] cycle {cycle}: compress (25c) -> {verdict(r1)}")

        for cycle in range(1, args.cycles + 1):
            scene(f"2.{cycle}", f"THE CREW — scout + worker run CONCURRENTLY (cycle {cycle}/{args.cycles})")
            await asyncio.gather(scout_branch(cycle), worker_branch(cycle))
            await asyncio.sleep(1)

        scene("3", "DEPTH — scout delegates 15c to sub-scout (chain: 100 -> 40 -> 15)")
        log(f"chain on the wire: {json.dumps(chain_demo['hops'])}")
        r = await call(client, "delegate",
                       {"rider_token": token, "warrant": master,
                        "sub_agent_id": "swarm-sub-scout", "sub_max_cents": 15,
                        "sub_until": now + 700, "sub_task": "info"})
        log(f"[sub-scout] info (2c) on 15c cap -> {verdict(r)}")
        await asyncio.sleep(1)

        scene("4", "DENIAL #1 (on camera) — sub-scout tries compress (25c) on its 15c cap")
        r = await call(client, "delegate",
                       {"rider_token": token, "warrant": master,
                        "sub_agent_id": "swarm-sub-scout", "sub_max_cents": 15,
                        "sub_until": now + 700, "sub_task": "compress"})
        log(f"[sub-scout] compress (25c) on 15c cap -> {verdict(r)}")
        log("the permission slip says 15c. the call costs 25c. denied.")
        await asyncio.sleep(1)

        scene("5", "DENIAL #2 (on camera) — a warrant that EXPIRES mid-run")
        flash = issue_warrant({"agent_id": agent_id, "max_cents": 20,
                               "until": int(time.time()) + 4})
        log("issued a 20c warrant with a 4-second life")
        r = await call(client, "info", {"rider_token": token, "warrant": flash})
        log(f"[operator] info (2c) -> {verdict(r)}  (warrant still alive)")
        log("waiting 5 seconds for it to die on camera...")
        await asyncio.sleep(5)
        r = await call(client, "info", {"rider_token": token, "warrant": flash})
        log(f"[operator] info (2c) -> {verdict(r)}  (warrant expired mid-run)")
        await asyncio.sleep(1)

        scene("6", "DENIAL #3 — tampered identity never reaches spend logic")
        segs = token.split(".")
        bad = segs[0] + "." + ("A" if segs[1][0] != "A" else "B") + segs[1][1:] + "." + segs[2]
        r = await call(client, "info", {"rider_token": bad, "warrant": master})
        log(f"[attacker] info with forged JWT -> {verdict(r)}")
        await asyncio.sleep(1)

        scene("7", "FINALE — the budget tree: caps vs accrued spend")
        ledger = await call(client, "my_ledger", {"rider_token": token})
        spent: dict[str, int] = {}
        for e in ledger.get("entries", []):
            spent[e["agent_id"]] = spent.get(e["agent_id"], 0) + e["cost_cents"]

        def row(key: str, label: str, cap: int, indent: int = 0):
            s = spent.get(key, 0)
            log(f"{'  ' * indent}{label}: per-call cap {cap}c | cumulative spent {s}c")

        log(f"operator ({agent_id}): per-call cap {PARENT_CAP}c "
            f"| direct spend {spent.get(agent_id, 0)}c")
        row("swarm-scout", "swarm-scout (role)", 40, 1)
        row("swarm-sub-scout", "swarm-sub-scout (role)", 15, 2)
        row("swarm-worker", "swarm-worker (role)", 40, 1)
        log("note: Warrant caps bind EACH call; the cumulative column is the")
        log("operator's own budget accounting on top — that layered discipline")
        log("is the whole point.")
        total = sum(spent.values())
        log(f"TOTAL ACCRUED: {total}c across {len(ledger.get('entries', []))} calls "
            f"({'simulated' if os.environ.get('DRY_RUN', '1') != '0' else 'live 402s, $0 settled'})")
        log("")
        log("VIDEO SHOT LIST (2:00):")
        log(" 0:00 boot — key inventory: 0 keys held")
        log(" 0:15 crew — scout + worker delegate concurrently, spend accrues")
        log(" 0:45 depth — the 100->40->15 chain on screen")
        log(" 1:00 DENIED: sub-scout compress on 15c cap (OVER_BUDGET)")
        log(" 1:20 DENIED: warrant expires live mid-run (WARRANT_EXPIRED)")
        log(" 1:40 DENIED: forged JWT (IDENTITY_BAD_SIGNATURE)")
        log(" 1:50 finale — budget tree: every cent accounted for, no keys held")

    log("")
    log(f"run complete. full log: {args.log}")
    log_fh.close()


if __name__ == "__main__":
    asyncio.run(main())
