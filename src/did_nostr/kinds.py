"""The four DID event kinds and their kind-specific validation (``DESIGN.md``
§3-§4, verification step 4).

The kind numbers are PROVISIONAL (``DESIGN.md`` §8). They live here, in one
place, so that a reassignment through the NIP process is a one-line change.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from .event import NostrEvent

__all__ = [
    "KIND_IDENTITY_ATTESTATION",
    "KIND_GUARDIAN_SET",
    "KIND_ROTATION_ATTESTATION",
    "KIND_ROTATION_CLAIM",
    "DID_KINDS",
    "METHODS",
    "CLAIM_ATTRIBUTES",
    "ROTATION_REASONS",
    "validate_kind",
]

KIND_IDENTITY_ATTESTATION = 30100
KIND_GUARDIAN_SET = 30101
KIND_ROTATION_ATTESTATION = 30102
KIND_ROTATION_CLAIM = 30103

DID_KINDS = (
    KIND_IDENTITY_ATTESTATION,
    KIND_GUARDIAN_SET,
    KIND_ROTATION_ATTESTATION,
    KIND_ROTATION_CLAIM,
)

#: §3.2 verification methods. Unknown methods are treated as no stronger than ``asserted``.
METHODS = ("in-person", "qr", "existing-channel", "guardian", "asserted")

#: §3.3 reserved claim attributes. ``claim`` attributes are otherwise open.
CLAIM_ATTRIBUTES = ("name", "same-as", "nip05", "not")

#: §4.2 rotation reasons.
ROTATION_REASONS = ("lost", "compromised", "planned")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# (ok, reason). reason is None on success.
Check = Tuple[bool, Optional[str]]
_OK: Check = (True, None)


def _first(ev: "NostrEvent", name: str) -> Optional[str]:
    for t in ev.tags:
        if t and t[0] == name:
            return t[1] if len(t) > 1 else None
    return None


def _all(ev: "NostrEvent", name: str) -> list:
    return [t[1] for t in ev.tags if len(t) > 1 and t[0] == name]


def _has(ev: "NostrEvent", name: str) -> bool:
    return any(t and t[0] == name for t in ev.tags)


def validate_kind(ev: "NostrEvent") -> Check:
    """Step 4: kind-specific validation. An event whose ``kind`` is not one of the
    DID kinds passes here unconditionally -- this library does not police generic
    Nostr events.
    """
    if ev.kind == KIND_IDENTITY_ATTESTATION:
        return _validate_attestation(ev)
    if ev.kind == KIND_GUARDIAN_SET:
        return _validate_guardian_set(ev)
    if ev.kind == KIND_ROTATION_ATTESTATION:
        return _validate_rotation_attestation(ev)
    if ev.kind == KIND_ROTATION_CLAIM:
        return _validate_rotation_claim(ev)
    return _OK


def _validate_attestation(ev: "NostrEvent") -> Check:
    d = _first(ev, "d")
    p = _first(ev, "p")
    if not d or not _HEX64.match(d):
        return (False, "kind 30100: `d` MUST be the subject pubkey (64 lowercase hex)")
    if not p or not _HEX64.match(p):
        return (False, "kind 30100: `p` MUST be the subject pubkey (64 lowercase hex)")
    if d != p:
        return (False, "kind 30100: `d` and `p` MUST both be the subject pubkey")

    claims = [t for t in ev.tags if t and t[0] == "claim"]
    if _has(ev, "revoked"):
        if claims:
            return (False, "kind 30100: a revocation MUST carry no `claim` tags")
        return _OK
    if len(claims) < 1:
        return (False, "kind 30100: requires >=1 `claim` tag")
    for c in claims:
        if len(c) < 3:
            return (False, 'kind 30100: each `claim` tag is ["claim", <attribute>, <value>]')
    if not _has(ev, "method"):
        return (False, "kind 30100: requires a `method` tag")
    return _OK


def _validate_guardian_set(ev: "NostrEvent") -> Check:
    if _first(ev, "d") != "guardians":
        return (False, 'kind 30101: `d` MUST be the literal "guardians"')
    guardians = _all(ev, "p")
    if len(guardians) < 1:
        return (False, "kind 30101: requires >=1 `p` (guardian) tag")
    if any(not _HEX64.match(g) for g in guardians):
        return (False, "kind 30101: guardian pubkeys MUST be 64 lowercase hex")
    if len(set(guardians)) != len(guardians):
        return (False, "kind 30101: duplicate guardian pubkey")
    m_raw = _first(ev, "threshold")
    if m_raw is None or not re.match(r"^\d+$", m_raw):
        return (False, "kind 30101: requires an integer `threshold`")
    m = int(m_raw)
    if m < 1 or m > len(guardians):
        return (False, "kind 30101: requires 1 <= M <= N")
    return _OK


def _validate_rotation_attestation(ev: "NostrEvent") -> Check:
    d = _first(ev, "d")
    p = _first(ev, "p")
    n = _first(ev, "new")
    if not d or not _HEX64.match(d):
        return (False, "kind 30102: `d` MUST be the old pubkey (64 lowercase hex)")
    if not p or not _HEX64.match(p):
        return (False, "kind 30102: `p` MUST be the old pubkey (64 lowercase hex)")
    if not n or not _HEX64.match(n):
        return (False, "kind 30102: `new` MUST be the endorsed pubkey (64 lowercase hex)")
    if not _has(ev, "method"):
        return (False, "kind 30102: requires a `method` tag")
    return _OK


def _validate_rotation_claim(ev: "NostrEvent") -> Check:
    d = _first(ev, "d")
    p = _first(ev, "p")
    if not d or not _HEX64.match(d):
        return (False, "kind 30103: `d` MUST be the old pubkey (64 lowercase hex)")
    if not p or not _HEX64.match(p):
        return (False, "kind 30103: `p` MUST be the old pubkey (64 lowercase hex)")
    if _first(ev, "reason") not in ROTATION_REASONS:
        return (False, "kind 30103: `reason` MUST be lost|compromised|planned")
    return _OK
