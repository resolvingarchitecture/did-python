"""Identity attestations -- the ``vouch`` primitive (``DESIGN.md`` §3,
drafts/attestations.md).

Kind 30100, signed by the attester, addressable on the subject's pubkey so an
attester holds exactly one current attestation per subject.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from .event import NostrEvent, sign_event
from .keys import normalize_pubkey
from .kinds import KIND_IDENTITY_ATTESTATION

__all__ = [
    "Claim",
    "AttestationInput",
    "ParsedAttestation",
    "create_attestation",
    "revoke_attestation",
    "parse_attestation",
    "is_expired",
]


@dataclass
class Claim:
    """One asserted attribute of the subject. The attribute list is open (§3.3)."""

    attribute: str
    value: str


@dataclass
class AttestationInput:
    #: The key being vouched for (hex or npub).
    subject: str
    #: At least one claim.
    claims: List[Claim] = field(default_factory=list)
    #: How the attester verified (§3.2).
    method: str = "asserted"
    #: Optional NIP-40 expiration, unix seconds.
    expiration: Optional[int] = None
    created_at: Optional[int] = None


def create_attestation(
    inp: AttestationInput,
    attester_secret_hex: str,
    aux_rand: Optional[bytes] = None,
) -> NostrEvent:
    """Build and sign a kind 30100 Identity Attestation."""
    if len(inp.claims) < 1:
        raise ValueError("an attestation needs at least one claim")
    subject = normalize_pubkey(inp.subject)
    tags: List[List[str]] = [["d", subject], ["p", subject]]
    for c in inp.claims:
        tags.append(["claim", c.attribute, c.value])
    tags.append(["method", str(inp.method)])
    if inp.expiration is not None:
        tags.append(["expiration", str(inp.expiration)])
    body = {"kind": KIND_IDENTITY_ATTESTATION, "tags": tags, "content": "", "created_at": inp.created_at}
    return sign_event(body, attester_secret_hex, aux_rand)


def revoke_attestation(
    subject: str,
    reason: str,
    attester_secret_hex: str,
    created_at: Optional[int] = None,
    aux_rand: Optional[bytes] = None,
) -> NostrEvent:
    """Build and sign a revocation: the addressable event is replaced with one
    that carries ``["revoked", <reason>]`` and no ``claim`` tags (§3.4). A
    verifier MUST treat this differently from a missing attestation.
    """
    s = normalize_pubkey(subject)
    body = {
        "kind": KIND_IDENTITY_ATTESTATION,
        "tags": [["d", s], ["p", s], ["revoked", reason]],
        "content": "",
        "created_at": created_at,
    }
    return sign_event(body, attester_secret_hex, aux_rand)


# --- reading ----------------------------------------------------------------


@dataclass
class ParsedAttestation:
    attester: str
    subject: str
    claims: List[Claim]
    method: Optional[str] = None
    expiration: Optional[int] = None
    revoked: Optional[str] = None


def parse_attestation(ev: NostrEvent) -> ParsedAttestation:
    """Structured view of a kind 30100 event. Does not verify -- call
    :func:`verify_event` first.
    """
    if ev.kind != KIND_IDENTITY_ATTESTATION:
        raise ValueError(f"not a kind {KIND_IDENTITY_ATTESTATION} event")
    exp = ev.tag("expiration")
    return ParsedAttestation(
        attester=ev.pubkey,
        subject=ev.tag("d") or "",
        claims=[
            Claim(t[1], t[2]) for t in ev.tags if t and t[0] == "claim" and len(t) >= 3
        ],
        method=ev.tag("method"),
        expiration=int(exp) if exp is not None else None,
        revoked=ev.tag("revoked"),
    )


def is_expired(ev: NostrEvent, at: Optional[int] = None) -> bool:
    """Is this attestation past its NIP-40 ``expiration`` at ``at`` (default: now)?"""
    if at is None:
        at = int(time.time())
    exp = ev.tag("expiration")
    return exp is not None and int(exp) <= at
