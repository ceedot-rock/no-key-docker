# Warrant DID Binding — Spec (spike)

**Status:** spike — `did:key` implemented, `did:web` specified, resolution deferred.
**Date:** 2026-10-11
**Context:** Cisco's AGNTCY is now a Linux Foundation project standardizing agent
interoperability. Its identity layer is W3C DIDs (`did:key`, `did:web`) plus
Verifiable Credentials, with Ed25519 signatures (`github.com/agntcy/identity`).
AGNTCY defines discovery, identity, messaging (SLIM), and observability — but no
authorization primitive: nothing that says what an agent may spend, and nothing
that delegates and attenuates that authority. This spec binds Warrant `agent_id`s
to DIDs, making Warrant the attenuating spend-authorization layer for
LF-standard agent identities.

## Design principles

1. **No wire-format change.** A narrow Warrant's `agent_id` is already an opaque
   non-empty string. A DID is just such a string beginning with `did:`. Every
   existing Warrant remains valid; attenuation semantics are untouched.
2. **Deny by default.** Any parse, resolution, or proof failure denies.
3. **did:key resolves offline.** The key is embedded in the identifier; no
   network, no trust anchor beyond the key itself.
4. **Proofs, not just names.** Naming a DID in a warrant is meaningless unless
   the caller proves control of the DID key. Enforcement requires a fresh
   challenge signature.

## Identifier model

- `agent_id` accepts any non-empty string (unchanged). Values matching
  `did:<method>:<method-specific-id>` are treated as DIDs.
- Chains may mix opaque ids and DIDs across hops; each hop's narrowing rule
  applies identically regardless of identifier type.

## did:key (implemented)

- Syntax: `did:key:z<base58btc(multicodec || pubkey)>`. This spike supports only
  Ed25519 keys: multicodec prefix `0xed01`, 32-byte public key (the AGNTCY
  choice). Other key types parse-fail with `DID_UNSUPPORTED`.
- Resolution: base58btc-decode the part after `z`, strip the 2-byte multicodec
  prefix, take the 32-byte Ed25519 public key. Pure local computation.
- Ownership proof (challenge-response):
  - Verifier generates a fresh random challenge (minimum 16 bytes, single-use).
  - Caller returns the Ed25519 signature over the raw challenge bytes.
  - Verifier checks `ed25519.verify(signature, challenge)` against the resolved key.
- Enforcement entry point:
  `gate_check_did(warrant, did, challenge, signature, cost_cents, now=None)`:
  1. Structural `verify_warrant` — deny on any failure (same error mapping as
     `gate_check`).
  2. Last-hop `agent_id == did`, else `AGENT_MISMATCH`.
  3. `did` must parse as a supported `did:key`, else `DID_UNSUPPORTED`.
  4. Challenge signature must verify, else `DID_PROOF_INVALID`.
  5. `cost_cents <= last-hop max_cents` and `now < until`, else
     `OVER_BUDGET` / `WARRANT_EXPIRED`.

## did:web (specified, deferred)

- Syntax `did:web:<host>[:port][:path...]` is accepted by `parse_did`.
- Resolution — HTTPS GET of `https://<host>/.well-known/did.json` (path segments
  map per the did:web spec), then select a `verificationMethod` with an
  Ed25519-capable key (`Ed25519VerificationKey2020` / `Multikey`).
- **Deferred:** fetch policy (timeouts, retries), TLS trust anchors, document
  caching/TTL, and key-rotation semantics all need decisions before
  implementation. `resolve_did` raises `DIDResolutionDeferred` for `did:web`.

## Non-goals

- No Verifiable Credential ("agent badge") issuance or verification. Badges
  attest *capabilities*; Warrants grant *spend*. Complementary layers.
- No DID rotation, revocation lists, or deactivation handling in this spike.
  `did:key` has no revocation: a compromised key burns the DID; rotation means a
  new DID and a new warrant chain.

## Security notes

- Challenge freshness is the replay defense: verifiers must never reuse a
  challenge. (Transport of the challenge is the integrator's job; the function
  takes it as bytes.)
- A verifier that skips step 4 reduces a DID warrant to a bearer token. The
  reference `gate_check_did` makes the proof mandatory — there is no
  proof-optional path.
