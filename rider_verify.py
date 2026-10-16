#!/usr/bin/env python3
"""
rider_verify.py — verify Agent-Rider identity JWTs against the live JWKS.

Real format (ceedot-rock/Agent-Rider src/lib/rider.ts):
- ES256 JWT, issuer "agentrider.dev", default TTL 900s (no grace). Live agents hold auto-renewed tokens; expiry here is per-token, not per-session.
- kid in the protected header; payload: agent_id, operator_id,
  level (L0-L4), scopes, jti, (+ iat/exp)
- Third-party verification: fetch the lab's published JWKS, jwtVerify with
  ES256, check iss, enforce expiry. No API key needed.

This module verifies; it never mints (minting needs the operator's ar_ key).
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Optional

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

JWKS_URL = "https://agentrider.fly.dev/.well-known/jwks.json"
ISSUER = "agentrider.dev"
_JWKS_TTL = 600  # seconds

_cache: dict = {"at": 0.0, "keys": {}}


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _jwk_to_key(jwk: dict):
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def get_jwks(force_refresh: bool = False) -> dict:
    """kid -> cryptography public key, cached for _JWKS_TTL seconds."""
    now = time.time()
    if force_refresh or now - _cache["at"] > _JWKS_TTL or not _cache["keys"]:
        r = requests.get(JWKS_URL, timeout=15)
        r.raise_for_status()
        doc = r.json()
        keys = {}
        for jwk in doc.get("keys", []):
            if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256" and jwk.get("kid"):
                keys[jwk["kid"]] = _jwk_to_key(jwk)
        if not keys:
            raise RuntimeError("JWKS contained no usable P-256 keys")
        _cache.update(at=now, keys=keys)
    return _cache["keys"]


def verify_rider_token(token: str, now: Optional[int] = None) -> dict:
    """
    Returns {"ok": True, "rider": {...payload...}} or
            {"ok": False, "code": ..., "detail": ...}.
    Deny by default on any failure.
    """
    now = int(time.time()) if now is None else now
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"ok": False, "code": "IDENTITY_MALFORMED",
                    "detail": "not a three-segment JWT"}
        header = json.loads(_b64url_decode(parts[0]))
        if header.get("alg") != "ES256":
            return {"ok": False, "code": "IDENTITY_BAD_ALG",
                    "detail": f"alg is {header.get('alg')!r}, want 'ES256'"}
        kid = header.get("kid")
        if not kid:
            return {"ok": False, "code": "IDENTITY_NO_KID", "detail": "missing kid"}
        keys = get_jwks()
        key = keys.get(kid)
        if key is None:  # one refresh in case of rotation, then deny
            key = get_jwks(force_refresh=True).get(kid)
            if key is None:
                return {"ok": False, "code": "IDENTITY_UNKNOWN_KID",
                        "detail": f"kid {kid!r} not in live JWKS"}
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        raw_sig = _b64url_decode(parts[2])
        if len(raw_sig) != 64:  # JWT uses raw R||S, not DER
            return {"ok": False, "code": "IDENTITY_MALFORMED",
                    "detail": f"bad ES256 signature length {len(raw_sig)}"}
        r_int = int.from_bytes(raw_sig[:32], "big")
        s_int = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r_int, s_int)
        try:
            key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return {"ok": False, "code": "IDENTITY_BAD_SIGNATURE",
                    "detail": "ES256 signature invalid"}
        payload = json.loads(_b64url_decode(parts[1]))
        if payload.get("iss") != ISSUER:
            return {"ok": False, "code": "IDENTITY_BAD_ISSUER",
                    "detail": f"iss is {payload.get('iss')!r}, want {ISSUER!r}"}
        exp = payload.get("exp")
        if not isinstance(exp, int) or now >= exp:
            return {"ok": False, "code": "IDENTITY_EXPIRED",
                    "detail": "token expired (15-min TTL, no grace)"}
        nbf = payload.get("nbf")
        if isinstance(nbf, int) and now < nbf:
            return {"ok": False, "code": "IDENTITY_NOT_YET_VALID",
                    "detail": "token not yet valid"}
        agent_id = payload.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            return {"ok": False, "code": "IDENTITY_MISSING_AGENT",
                    "detail": "no agent_id in payload"}
        return {"ok": True, "rider": payload}
    except (ValueError, KeyError, TypeError) as e:
        return {"ok": False, "code": "IDENTITY_MALFORMED", "detail": str(e)}
    except requests.RequestException as e:
        return {"ok": False, "code": "IDENTITY_JWKS_UNREACHABLE", "detail": str(e)}
