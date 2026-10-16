#!/usr/bin/env python3
"""
did_binding.py — bind Warrant agent_ids to W3C DIDs (AGNTCY identity layer).

did:key (Ed25519) is fully implemented: offline resolution straight from the
identifier, plus challenge-response ownership proofs for spend-gate
enforcement. did:web parses but resolution is deferred (see SPEC.md).

No new dependencies: base58btc decode is inlined (~20 lines), Ed25519 comes
from the `cryptography` package already in the project venv.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import warrant_lib
from warrant_lib import WarrantError

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

DID_UNSUPPORTED = "DID_UNSUPPORTED"          # method or key type we don't handle
DID_MALFORMED = "DID_MALFORMED"              # syntactically invalid DID
DID_PROOF_INVALID = "DID_PROOF_INVALID"      # challenge signature didn't verify
DID_RESOLUTION_DEFERRED = "DID_RESOLUTION_DEFERRED"  # did:web, not yet implemented


class DIDError(Exception):
    """Raised with one of the DID_* codes above."""


# ---------------------------------------------------------------------------
# base58btc (inline — avoids a new dependency)
# ---------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        try:
            n = n * 58 + _B58.index(ch)
        except ValueError:
            raise DIDError(DID_MALFORMED)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + (out or "")


# ---------------------------------------------------------------------------
# DID parsing
# ---------------------------------------------------------------------------

_ED25519_MULTICODEC = b"\xed\x01"


def parse_did(did: str) -> dict:
    """
    Parse a DID string. Returns {"method": ..., "msid": ...}.
    Raises DIDError(DID_MALFORMED) on bad syntax.
    """
    if not isinstance(did, str) or not did.startswith("did:"):
        raise DIDError(DID_MALFORMED)
    parts = did.split(":")
    if len(parts) < 3 or not parts[1] or not parts[2]:
        raise DIDError(DID_MALFORMED)
    return {"method": parts[1], "msid": ":".join(parts[2:])}


def did_key_pubkey(did: str) -> bytes:
    """
    Resolve a did:key to its raw 32-byte Ed25519 public key. Offline.
    Raises DIDError(DID_MALFORMED | DID_UNSUPPORTED).
    """
    p = parse_did(did)
    if p["method"] != "key":
        raise DIDError(DID_RESOLUTION_DEFERRED if p["method"] == "web" else DID_UNSUPPORTED)
    msid = p["msid"]
    if not msid.startswith("z"):
        raise DIDError(DID_MALFORMED)
    raw = _b58decode(msid[1:])
    if len(raw) != 34 or raw[:2] != _ED25519_MULTICODEC:
        # Only Ed25519 (0xed01) in this spike.
        raise DIDError(DID_UNSUPPORTED)
    return raw[2:]


def did_key_from_pubkey(pubkey: bytes) -> str:
    """Build a did:key identifier from a 32-byte Ed25519 public key."""
    if not isinstance(pubkey, bytes) or len(pubkey) != 32:
        raise DIDError(DID_MALFORMED)
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + pubkey)


def resolve_did(did: str) -> bytes:
    """
    Resolve a DID to a 32-byte Ed25519 public key.
    did:key -> offline. did:web -> DIDError(DID_RESOLUTION_DEFERRED).
    Anything else -> DIDError(DID_UNSUPPORTED).
    """
    return did_key_pubkey(did)  # raises appropriately per method


# ---------------------------------------------------------------------------
# Ownership proofs (challenge-response)
# ---------------------------------------------------------------------------

CHALLENGE_BYTES = 24


def new_challenge(n: int = CHALLENGE_BYTES) -> bytes:
    """Verifier-side: fresh random challenge. Single-use; never reuse."""
    if n < 16:
        raise DIDError(DID_MALFORMED)
    return os.urandom(n)


def sign_challenge(privkey: Ed25519PrivateKey, challenge: bytes) -> bytes:
    """Caller-side helper (agents sign with their DID key)."""
    return privkey.sign(challenge)


def verify_proof(did: str, challenge: bytes, signature: bytes) -> bool:
    """
    Check an Ed25519 challenge signature against the DID's key.
    Returns True/False — never raises on a bad signature.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(resolve_did(did))
        pub.verify(signature, challenge)
        return True
    except (DIDError, InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Spend-gate enforcement for DID-identified agents
# ---------------------------------------------------------------------------

def gate_check_did(warrant: Any, did: str, challenge: bytes, signature: bytes,
                   cost_cents: int, now: Optional[int] = None) -> dict:
    """
    Full enforcement for a DID-named warrant. Returns:
      {"ok": True, "body": {...}, "remaining_cents": int}
      {"ok": False, "code": "WARRANT_DENIED"|"WARRANT_EXPIRED"|"OVER_BUDGET"|
                             "AGENT_MISMATCH"|"DID_UNSUPPORTED"|
                             "DID_RESOLUTION_DEFERRED"|"DID_PROOF_INVALID",
       "detail": str}
    Deny by default on any failure. The DID ownership proof is mandatory —
    there is no proof-optional path.
    """
    if isinstance(cost_cents, bool) or not isinstance(cost_cents, int) or cost_cents < 0:
        return {"ok": False, "code": "WARRANT_DENIED", "detail": "invalid cost_cents"}

    v = warrant_lib.verify_warrant(warrant, now)
    if not v["ok"]:
        code = "WARRANT_EXPIRED" if v["error"] == "warrant_expired" else "WARRANT_DENIED"
        return {"ok": False, "code": code, "detail": v["error"]}
    body = v["body"]

    if body["agent_id"] != did:
        return {"ok": False, "code": "AGENT_MISMATCH",
                "detail": f"warrant names {body['agent_id']!r}, caller is {did!r}"}

    try:
        parse_did(did)
        resolve_did(did)
    except DIDError as e:
        code = str(e) or DID_UNSUPPORTED
        return {"ok": False, "code": code, "detail": f"DID resolution failed: {code}"}

    if not isinstance(challenge, bytes) or len(challenge) < 16:
        return {"ok": False, "code": DID_PROOF_INVALID, "detail": "bad challenge"}
    if not verify_proof(did, challenge, signature):
        return {"ok": False, "code": DID_PROOF_INVALID,
                "detail": "challenge signature did not verify against DID key"}

    now = int(time.time()) if now is None else now
    if cost_cents > body["max_cents"]:
        return {"ok": False, "code": "OVER_BUDGET",
                "detail": f"cost {cost_cents}c exceeds warrant cap {body['max_cents']}c"}
    return {"ok": True, "body": body, "remaining_cents": body["max_cents"]}
