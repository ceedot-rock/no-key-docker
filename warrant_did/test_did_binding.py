#!/usr/bin/env python3
"""Tests for the Warrant DID binding (did:key implemented, did:web deferred)."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import warrant_lib
from warrant_lib import issue_warrant, attenuate
from did_binding import (
    DIDError, DID_MALFORMED, DID_PROOF_INVALID, DID_UNSUPPORTED,
    DID_RESOLUTION_DEFERRED,
    parse_did, did_key_pubkey, did_key_from_pubkey, resolve_did,
    new_challenge, sign_challenge, verify_proof, gate_check_did,
)

NOW = int(time.time())
FUTURE = NOW + 3600


def fresh_did():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return did_key_from_pubkey(pub), priv


def test_did_key_roundtrip():
    did, _ = fresh_did()
    assert did.startswith("did:key:z")
    p = parse_did(did)
    assert p["method"] == "key"
    pub = did_key_pubkey(did)
    assert len(pub) == 32


def test_known_did_key_vector():
    # Well-known did:key for an Ed25519 key (spec example shape check).
    did, priv = fresh_did()
    pub = priv.public_key().public_bytes_raw()
    assert did_key_pubkey(did_key_from_pubkey(pub)) == pub


def test_reject_bad_syntax():
    for bad in ["", "did:", "did:key:", "not-a-did", 42, None]:
        try:
            parse_did(bad)
            raise AssertionError(f"accepted {bad!r}")
        except DIDError:
            pass
    # Shape-valid but bad base58: parse accepts the shape, resolution rejects it.
    assert parse_did("did:key:!!!")["method"] == "key"
    try:
        did_key_pubkey("did:key:!!!")
        raise AssertionError("resolved bad base58")
    except DIDError as e:
        assert str(e) == DID_MALFORMED, str(e)


def test_reject_non_ed25519_key():
    # secp256k1 multicodec prefix 0xe701 with 33 bytes -> unsupported here.
    from did_binding import _b58encode
    did = "did:key:z" + _b58encode(b"\xe7\x01" + b"\x02" * 33)
    try:
        did_key_pubkey(did)
        raise AssertionError("accepted secp256k1")
    except DIDError as e:
        assert str(e) == DID_UNSUPPORTED, str(e)


def test_did_web_parses_but_defers():
    p = parse_did("did:web:example.com")
    assert p["method"] == "web"
    try:
        resolve_did("did:web:example.com")
        raise AssertionError("resolved did:web")
    except DIDError as e:
        assert str(e) == DID_RESOLUTION_DEFERRED, str(e)


def test_challenge_proof_happy_path():
    did, priv = fresh_did()
    chal = new_challenge()
    sig = sign_challenge(priv, chal)
    assert verify_proof(did, chal, sig) is True


def test_wrong_key_proof_fails():
    did, _ = fresh_did()
    _, other_priv = fresh_did()
    chal = new_challenge()
    assert verify_proof(did, chal, sign_challenge(other_priv, chal)) is False


def test_tampered_challenge_fails():
    did, priv = fresh_did()
    chal = new_challenge()
    sig = sign_challenge(priv, chal)
    bad = bytearray(chal)
    bad[0] ^= 1
    assert verify_proof(did, bytes(bad), sig) is False


def test_gate_check_did_full_chain():
    root_did, _ = fresh_did()
    mid_did, _ = fresh_did()
    leaf_did, leaf_priv = fresh_did()
    w = issue_warrant({"agent_id": root_did, "max_cents": 100, "until": FUTURE})
    w = attenuate(w, {"agent_id": mid_did, "max_cents": 40, "until": FUTURE})
    w = attenuate(w, {"agent_id": leaf_did, "max_cents": 15, "until": FUTURE})
    chal = new_challenge()
    sig = sign_challenge(leaf_priv, chal)
    r = gate_check_did(w, leaf_did, chal, sig, 10, NOW)
    assert r["ok"], r
    assert r["remaining_cents"] == 15


def test_gate_check_did_over_budget():
    leaf_did, leaf_priv = fresh_did()
    w = issue_warrant({"agent_id": leaf_did, "max_cents": 15, "until": FUTURE})
    chal = new_challenge()
    r = gate_check_did(w, leaf_did, chal, sign_challenge(leaf_priv, chal), 16, NOW)
    assert not r["ok"] and r["code"] == "OVER_BUDGET", r


def test_gate_check_did_bad_proof_denied():
    leaf_did, _ = fresh_did()
    _, other_priv = fresh_did()
    w = issue_warrant({"agent_id": leaf_did, "max_cents": 15, "until": FUTURE})
    chal = new_challenge()
    r = gate_check_did(w, leaf_did, chal, sign_challenge(other_priv, chal), 10, NOW)
    assert not r["ok"] and r["code"] == DID_PROOF_INVALID, r


def test_gate_check_did_wrong_did():
    leaf_did, leaf_priv = fresh_did()
    other_did, _ = fresh_did()
    w = issue_warrant({"agent_id": leaf_did, "max_cents": 15, "until": FUTURE})
    chal = new_challenge()
    r = gate_check_did(w, other_did, chal, sign_challenge(leaf_priv, chal), 10, NOW)
    assert not r["ok"] and r["code"] == "AGENT_MISMATCH", r


def test_gate_check_did_widening_still_rejected():
    a, _ = fresh_did()
    b, _ = fresh_did()
    w = issue_warrant({"agent_id": a, "max_cents": 10, "until": FUTURE})
    try:
        attenuate(w, {"agent_id": b, "max_cents": 11, "until": FUTURE})
        raise AssertionError("widening accepted")
    except warrant_lib.WarrantError as e:
        assert str(e) == "warrant_widen_cents"


def test_gate_check_did_expired():
    leaf_did, leaf_priv = fresh_did()
    w = issue_warrant({"agent_id": leaf_did, "max_cents": 15, "until": NOW - 1})
    chal = new_challenge()
    r = gate_check_did(w, leaf_did, chal, sign_challenge(leaf_priv, chal), 10, NOW)
    assert not r["ok"] and r["code"] == "WARRANT_EXPIRED", r


def test_gate_check_did_web_deferred():
    did = "did:web:example.com"
    w = issue_warrant({"agent_id": did, "max_cents": 15, "until": FUTURE})
    r = gate_check_did(w, did, new_challenge(), b"\x00" * 64, 10, NOW)
    assert not r["ok"] and r["code"] == DID_RESOLUTION_DEFERRED, r


def test_mixed_chain_opaque_and_did():
    leaf_did, leaf_priv = fresh_did()
    w = issue_warrant({"agent_id": "root-opaque-id", "max_cents": 100, "until": FUTURE})
    w = attenuate(w, {"agent_id": leaf_did, "max_cents": 15, "until": FUTURE})
    chal = new_challenge()
    r = gate_check_did(w, leaf_did, chal, sign_challenge(leaf_priv, chal), 10, NOW)
    assert r["ok"], r


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as e:
            failed += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
