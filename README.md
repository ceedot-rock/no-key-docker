# The agent that spends money without holding keys

**Collabnix $250 Agent Challenge — track: 🔐 No Keys Allowed**

An agent that makes real paid API calls where every call is authorized by a
*signed Warrant* (a spend mandate) and the agent authenticates with a verified
*Agent-Rider* identity. The agent never holds a wallet private key or an API
token for the paid service — the Warrant **is** the permission slip, and
budgets strictly shrink as authority delegates down a chain.

The paid service is real: Slid Phi Labs' live x402 endpoints
(`https://rider-x402.fly.dev`) — compress 25¢, decompress 10¢, info 2¢,
settled in USDC on Base.

## Architecture

```
                    ┌──────────────────────────────┐
  demo agent        │        warrant-gate          │      paid API
  ──────────       │        (FastMCP server)      │      ─────────
  holds:           │                              │   rider-x402.fly.dev
   · Rider JWT     │  1. verify identity (JWKS)   │   /api/x402/pcc/info       2¢
     (15-min TTL)  │  2. verify Warrant chain     │   /api/x402/pcc/compress  25¢
   · Warrants      │  3. enforce: agent match +   │   /api/x402/pcc/decompress 10¢
   · 0 API keys    │     cost ≤ cap + not expired │
   · 0 wallets  ──▶│  4. proxy upstream (or 402)  │──▶ 402 → terms surfaced,
                    └──────────────────────────────┘     never auto-settled
```

Identity is verified per call against the **live** JWKS
(`https://agentrider.fly.dev/.well-known/jwks.json`, ES256/P-256) — no API key
needed for verification. Spend is enforced against the narrow Warrant with the
exact reference semantics (`{v:1, kind:"spl-narrow", authority, hops}`):
integer-cent caps, monotonic non-widening hops, expiry, deny by default.

## The demo (what the 2-minute video shows)

`demo.py` runs six scenes against the gate, in order:

| # | Scene | Result |
|---|-------|--------|
| 1 | `info` (2¢) on a 50¢ warrant | **ALLOWED** |
| 2 | `compress` (25¢) on a 50¢ warrant | **ALLOWED** |
| 3 | `compress` (25¢) on a 10¢ warrant | **DENIED** `OVER_BUDGET` |
| 4 | `info` on an expired warrant | **DENIED** `WARRANT_EXPIRED` |
| 5 | `info` with a tampered JWT | **DENIED** `IDENTITY_BAD_SIGNATURE` (before spend logic runs) |
| 6 | delegate: parent 50¢ → sub-agent 10¢; sub runs `info` ✅, sub tries `compress` | **DENIED** `SUB_OVER_BUDGET` |

It ends on the spend ledger and the key inventory: **0 API keys, 0 wallet
keys held at any point.**

## The full video run: `swarm.py`

`demo.py` is the smoke test. `swarm.py` is the sustained, unattended run that
produces the complete 2-minute video:

```bash
.venv/bin/python swarm.py [--cycles N] [--live-spend] [--log demo_swarm.log]
```

Eight scenes, one verified operator identity, sub-agents as delegated roles:

- **0 boot** — key inventory: 0 keys held; the delegation model stated plainly
- **1 operator baseline** — `info` (2¢) on the 100¢ master warrant
- **2.1…2.N the crew** — scout (40¢) + worker (40¢) run **concurrently**
  (`asyncio.gather`), cycles repeat so spend visibly accrues
- **3 depth** — the 100¢ → 40¢ → 15¢ chain on screen; sub-scout runs `info`
- **4 denial #1, on camera** — sub-scout tries `compress` (25¢) on its 15¢ cap
- **5 denial #2, on camera** — a 20¢ warrant with a 4-second life expires
  mid-run (allowed → 5s wait → `WARRANT_EXPIRED`)
- **6 denial #3** — tampered JWT dies at identity check, before spend logic
- **7 finale** — the budget tree: per-call caps vs cumulative accrued spend,
  plus a timestamped **video shot list**

Everything is timestamp-logged to stdout and `demo_swarm.log`.
Honest framing, printed in the run: one verified operator identity;
sub-agents are delegated roles acting through `delegate` on the parent's
verified authority — which is exactly what the Warrant model is for.

## How to repeat the build

```bash
git clone <this repo> && cd docker-agent-challenge
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 1. unit tests: the exact Warrant semantics (10 tests)
.venv/bin/python test_warrant.py

# 2. the demo (dry-run: upstream SIMULATED, nothing is spent)
export AGENT_RIDER_API_KEY=<your ar_ key>   # mints a fresh 15-min JWT
.venv/bin/python demo.py

# 3. live mode: hits the real x402 endpoints. Unpaid calls return HTTP 402
#    with payment terms, which are printed — never settled. Still spends $0.
.venv/bin/python demo.py --live-spend

# 4. standalone server (streamable HTTP, for the sandbox)
DRY_RUN=1 .venv/bin/python server.py          # :8000
docker build -t warrant-gate-demo .          # image not built here (no daemon)
docker run -p 8000:8000 warrant-gate-demo
```

Identity alternatives: `--rider-token PATH` or `RIDER_TOKEN` env instead of
minting. The repo contains no keys, tokens, or credentials of any kind.

## The spend story

- **Dry-run (default):** every upstream call is simulated; the ledger records
  what *would* have been spent (demo total: 27¢). Safe to run anywhere.
- **Live (`--live-spend`):** the server POSTs the real endpoints. The service
  answers `402 Payment Required` with x402 terms (verified: 2¢ USDC on Base
  for `info`, 25¢ for `compress`, with exact `payTo`/asset/chain fields).
  The demo prints the terms as proof the price is real and stops — settlement
  requires a funded wallet and is the operator's explicit step, never the
  agent's. The agent literally *cannot* pay: it holds no keys.
- **Challenge spend:** the build itself cost $0. Cloud sandbox spend only
  begins at the deploy step below.

## Files

| File | What |
|------|------|
| `warrant_lib.py` | Warrant semantics: issue / attenuate / verify / spend-gate (exact port of the reference implementation, incl. error strings) |
| `rider_verify.py` | ES256 JWT verification against the live JWKS (cached, rotation-aware) |
| `gate.py` | One combined gate: identity first, then Warrant. Deny by default |
| `server.py` | FastMCP server: `info`, `compress`, `decompress`, `delegate`, `my_ledger` (ledger tracks `delegated_by`, so the budget tree is real) |
| `demo.py` | The demo agent: six scenes, dry-run default, `--live-spend` for real 402s |
| `swarm.py` | The full video run: 8 scenes, concurrent crew, 3-level chain, both denials on camera, budget-tree finale + shot list |
| `test_warrant.py` | 10 unit tests over the Warrant edge cases |
| `Dockerfile` | Sandbox-ready image (`python server.py` on :8000) |

## TODO — Corey's steps (not done here, on purpose)

- [x] **Claim the $250 credit** — done 2026-10-10 at docker.com/c/sbx-promo
- [ ] **Sandbox deploy:** `sbx --cloud run` / `docker build && docker run` the
      image above; point the demo at the sandbox URL instead of in-process
- [ ] **Demo video (2 min):** record `demo.py` output; suggested shot list is
      the six-scene table above, ending on the ledger + key inventory
- [ ] **Spend screenshot:** sandbox billing page with private details blanked
- [ ] **Submission form:** the Collabnix form, by Oct 31, 11:59 PM IST

No Docker/account signups were created by this build, and nothing was
submitted anywhere. The build is pure code + docs.
