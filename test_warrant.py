#!/usr/bin/env python3
"""Unit tests for warrant_lib.py — the exact narrow.ts semantics."""

import time

from warrant_lib import (
    WarrantError, attenuate, gate_check, issue_warrant, parse_warrant,
    remaining_cents, verify_warrant,
)

NOW = int(time.time())
A = {"agent_id": "agent-a", "max_cents": 50, "until": NOW + 900}


def test_issue_verify_roundtrip():
    w = issue_warrant(A)
    v = verify_warrant(w, NOW)
    assert v["ok"] and v["body"] == A, v


def test_attenuate_shrinks():
    w = issue_warrant(A)
    w2 = attenuate(w, {"agent_id": "agent-b", "max_cents": 10, "until": NOW + 100})
    v = verify_warrant(w2, NOW)
    assert v["ok"] and v["body"]["agent_id"] == "agent-b", v


def test_widen_cents_rejected():
    w = issue_warrant(A)
    try:
        attenuate(w, {"agent_id": "agent-b", "max_cents": 51, "until": NOW + 100})
    except WarrantError as e:
        assert str(e) == "warrant_widen_cents", e
    else:
        raise AssertionError("widening cents was allowed")


def test_widen_until_rejected():
    w = issue_warrant(A)
    try:
        attenuate(w, {"agent_id": "agent-b", "max_cents": 10, "until": NOW + 901})
    except WarrantError as e:
        assert str(e) == "warrant_widen_until", e
    else:
        raise AssertionError("widening until was allowed")


def test_equal_hop_allowed():
    # equal is not widening
    w = attenuate(issue_warrant(A), {"agent_id": "b", "max_cents": 50, "until": NOW + 900})
    assert verify_warrant(w, NOW)["ok"]


def test_expired():
    w = issue_warrant({"agent_id": "a", "max_cents": 50, "until": NOW - 1})
    v = verify_warrant(w, NOW)
    assert not v["ok"] and v["error"] == "warrant_expired", v


def test_hand_built_widening_chain_fails_verify():
    # attacker crafts a chain directly instead of via attenuate()
    w = {"v": 1, "kind": "spl-narrow", "authority": A,
         "hops": [{"agent_id": "b", "max_cents": 9999, "until": NOW + 100}]}
    v = verify_warrant(w, NOW)
    assert not v["ok"] and v["error"] == "warrant_widen_cents", v


def test_bad_shapes():
    assert verify_warrant(None, NOW)["error"] == "warrant_kind"
    assert verify_warrant({"v": 1, "kind": "other", "authority": A, "hops": []}, NOW)["error"] == "warrant_kind"
    assert verify_warrant({"v": 2, "kind": "spl-narrow", "authority": A, "hops": []}, NOW)["error"] == "warrant_kind"
    for bad in [{"agent_id": "a", "max_cents": -1, "until": NOW + 1},
                {"agent_id": "a", "max_cents": 1.5, "until": NOW + 1},
                {"agent_id": "a", "max_cents": True, "until": NOW + 1},
                {"agent_id": "", "max_cents": 1, "until": NOW + 1},
                {"agent_id": "a", "max_cents": 1, "until": 0}]:
        try:
            issue_warrant(bad)
        except WarrantError:
            pass
        else:
            raise AssertionError(f"bad authority accepted: {bad}")


def test_gate_enforcement():
    w = issue_warrant(A)
    ok = gate_check(w, "agent-a", 25, NOW)
    assert ok["ok"] and ok["remaining_cents"] == 50, ok
    over = gate_check(w, "agent-a", 51, NOW)
    assert not over["ok"] and over["code"] == "OVER_BUDGET", over
    wrong = gate_check(w, "agent-evil", 1, NOW)
    assert not wrong["ok"] and wrong["code"] == "AGENT_MISMATCH", wrong
    assert remaining_cents(w) == 50
    assert remaining_cents(issue_warrant({"agent_id": "a", "max_cents": 1, "until": NOW - 1})) == 0


def test_parse():
    assert parse_warrant(issue_warrant(A)) is not None
    assert parse_warrant({"kind": "spl-narrow"}) is None
    assert parse_warrant("nope") is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
