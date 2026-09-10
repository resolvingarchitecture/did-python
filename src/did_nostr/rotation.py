"""Guardians, rotation and recovery (``DESIGN.md`` §4, drafts/social-recovery.md).

  - kind 30101 Guardian Set         -- signed by the root identity
  - kind 30103 Rotation Claim       -- signed by the new key
  - kind 30102 Rotation Attestation -- signed by a guardian, one per guardian

Plus :func:`evaluate_rotation`, the normative acceptance rule (§4.3). This is a
direct port of ``did-vectors/acceptance.py``; the two are kept in step.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .event import NostrEvent, schnorr_sign_raw, schnorr_verify_raw, sign_event
from .keys import normalize_pubkey, public_key_from_secret
from .kinds import (
    KIND_GUARDIAN_SET,
    KIND_ROTATION_ATTESTATION,
    KIND_ROTATION_CLAIM,
)

__all__ = [
    "DEFAULT_COOLDOWN_SECONDS",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "GuardianSetInput",
    "RotationClaimInput",
    "RotationAttestationInput",
    "RotationVerdict",
    "EvaluateOptions",
    "create_guardian_set",
    "create_rotation_claim",
    "create_rotation_attestation",
    "prev_sig",
    "evaluate_rotation",
]

#: Default guardian-set cool-down: 7 days, in seconds (§4.3 clause 5).
DEFAULT_COOLDOWN_SECONDS = 7 * 24 * 60 * 60

#: Small allowance for a Rotation Claim dated slightly ahead of the verifier's clock.
DEFAULT_CLOCK_SKEW_SECONDS = 5 * 60

_DIGITS = re.compile(r"^\d+$")


# --- builders --------------------------------------------------------------


@dataclass
class GuardianSetInput:
    guardians: List[str] = field(default_factory=list)  # hex or npub
    threshold: int = 1
    created_at: Optional[int] = None


def create_guardian_set(
    inp: GuardianSetInput,
    root_secret_hex: str,
    aux_rand: Optional[bytes] = None,
) -> NostrEvent:
    """Build and sign a kind 30101 Guardian Set."""
    guardians = [normalize_pubkey(g) for g in inp.guardians]
    if len(guardians) < 1:
        raise ValueError("a guardian set needs at least one guardian")
    if len(set(guardians)) != len(guardians):
        raise ValueError("duplicate guardian")
    if not isinstance(inp.threshold, int) or inp.threshold < 1 or inp.threshold > len(guardians):
        raise ValueError("threshold must be an integer in 1..N")
    tags: List[List[str]] = [["d", "guardians"]]
    tags += [["p", g] for g in guardians]
    tags.append(["threshold", str(inp.threshold)])
    return sign_event(
        {"kind": KIND_GUARDIAN_SET, "tags": tags, "content": "", "created_at": inp.created_at},
        root_secret_hex,
        aux_rand,
    )


@dataclass
class RotationClaimInput:
    old_pubkey: str  # hex or npub
    reason: str
    #: Include a ``prev-sig`` when the old key is still held (self-authorised, §4.3).
    old_secret_hex_for_prev_sig: Optional[str] = None
    created_at: Optional[int] = None


def create_rotation_claim(
    inp: RotationClaimInput,
    new_secret_hex: str,
    aux_rand: Optional[bytes] = None,
) -> NostrEvent:
    """Build and sign a kind 30103 Rotation Claim (signed by the NEW key)."""
    old = normalize_pubkey(inp.old_pubkey)
    tags: List[List[str]] = [["d", old], ["p", old], ["reason", inp.reason]]
    if inp.old_secret_hex_for_prev_sig:
        new_pubkey = public_key_from_secret(new_secret_hex)
        tags.append(["prev-sig", schnorr_sign_raw(new_pubkey, inp.old_secret_hex_for_prev_sig)])
    return sign_event(
        {"kind": KIND_ROTATION_CLAIM, "tags": tags, "content": "", "created_at": inp.created_at},
        new_secret_hex,
        aux_rand,
    )


@dataclass
class RotationAttestationInput:
    old_pubkey: str  # hex or npub
    new_pubkey: str  # hex or npub
    method: str = "guardian"
    created_at: Optional[int] = None


def create_rotation_attestation(
    inp: RotationAttestationInput,
    guardian_secret_hex: str,
    aux_rand: Optional[bytes] = None,
) -> NostrEvent:
    """Build and sign a kind 30102 Rotation Attestation (signed by a GUARDIAN)."""
    old = normalize_pubkey(inp.old_pubkey)
    return sign_event(
        {
            "kind": KIND_ROTATION_ATTESTATION,
            "tags": [
                ["d", old],
                ["p", old],
                ["new", normalize_pubkey(inp.new_pubkey)],
                ["method", str(inp.method)],
            ],
            "content": "",
            "created_at": inp.created_at,
        },
        guardian_secret_hex,
        aux_rand,
    )


def prev_sig(new_pubkey_hex: str, old_secret_hex: str) -> str:
    """Compute a ``prev-sig``: BIP-340 by the old key over the 32 raw new-pubkey bytes."""
    return schnorr_sign_raw(normalize_pubkey(new_pubkey_hex), old_secret_hex)


# --- the acceptance rule (§4.3) -------------------------------------------


@dataclass
class RotationVerdict:
    accepted: bool
    reason: str
    #: On acceptance: the successor key a client should migrate to.
    new: Optional[str] = None
    #: On acceptance: the key being rotated away from.
    old: Optional[str] = None

    def __bool__(self) -> bool:
        return self.accepted


@dataclass
class EvaluateOptions:
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS
    #: Verifier's notion of "now"; a claim dated beyond this + skew is rejected.
    now: Optional[int] = None
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS


def evaluate_rotation(
    events: Sequence[NostrEvent],
    opts: Optional[EvaluateOptions] = None,
) -> RotationVerdict:
    """Decide whether some ``new`` key is the accepted successor of some ``old``
    key, given a bag of events. Assumes every event is already well-formed and
    its signature and id verified -- run :func:`verify_event` on each first.

    Mirrors ``did-vectors/acceptance.py``.
    """
    opts = opts or EvaluateOptions()
    cooldown = opts.cooldown_seconds
    skew = opts.clock_skew_seconds

    # clause 4: a Rotation Claim (kind 30103). Take the earliest.
    claims = sorted(
        (e for e in events if e.kind == KIND_ROTATION_CLAIM), key=lambda e: e.created_at
    )
    if not claims:
        return RotationVerdict(False, "clause 4: no kind 30103 Rotation Claim")
    claim = claims[0]
    old = claim.tag("d")
    nxt = claim.pubkey
    ct = claim.created_at
    if not old:
        return RotationVerdict(False, "clause 4: Rotation Claim has no `d` (old pubkey)")
    if nxt == old:
        return RotationVerdict(
            False, "clause 4: Rotation Claim does not name a distinct successor key"
        )
    if opts.now is not None and ct > opts.now + skew:
        return RotationVerdict(False, "clause 5: Rotation Claim is dated in the future")

    # clause 4 (self-authorised): a valid prev-sig by old over the new pubkey.
    ps = claim.tag("prev-sig")
    if ps is not None:
        if schnorr_verify_raw(ps, nxt, old):
            return RotationVerdict(
                True, "self-authorised: valid prev-sig by old over new", new=nxt, old=old
            )
        # invalid prev-sig -> ignored; fall through to the guardian path

    # clause 1: a Guardian Set (kind 30101, d=guardians) signed by old.
    gsets = [
        e
        for e in events
        if e.kind == KIND_GUARDIAN_SET and e.pubkey == old and e.tag("d") == "guardians"
    ]
    if not gsets:
        return RotationVerdict(False, "clause 1: no Guardian Set signed by old")

    # clause 5: use the most recent set that is both current at the claim and past its cool-down.
    eligible = [g for g in gsets if g.created_at + cooldown <= ct]
    if not eligible:
        return RotationVerdict(
            False,
            "clause 5: no Guardian Set is both current at the claim and past its cool-down",
        )
    gset = max(eligible, key=lambda g: g.created_at)
    guardians: Set[str] = set(gset.tag_values("p"))
    m_raw = gset.tag("threshold")
    if m_raw is None or not _DIGITS.match(m_raw):
        return RotationVerdict(False, "clause 1: Guardian Set has no valid threshold")
    threshold = int(m_raw)
    if not 1 <= threshold <= len(guardians):
        return RotationVerdict(False, "clause 1: Guardian Set threshold out of range 1..N")

    # clauses 2 + 3: >= M distinct guardians, each signing their own kind 30102
    #                for this old, all naming an identical new.
    endorsers: Dict[str, Set[str]] = {}
    ignored_non_guardian = 0
    for a in events:
        if a.kind != KIND_ROTATION_ATTESTATION or a.tag("d") != old:
            continue
        if a.pubkey not in guardians:
            ignored_non_guardian += 1
            continue
        n = a.tag("new")
        if n is None:
            continue
        endorsers.setdefault(n, set()).add(a.pubkey)

    have = len(endorsers.get(nxt, set()))
    if have >= threshold:
        return RotationVerdict(
            True,
            f"guardian path: {have} of {threshold} distinct guardians endorsed new",
            new=nxt,
            old=old,
        )
    note = (
        f" ({ignored_non_guardian} endorsement(s) ignored: not in guardian set)"
        if ignored_non_guardian
        else ""
    )
    return RotationVerdict(
        False,
        f"clause 2: {have} distinct guardians endorsed the claimed new key, need {threshold}{note}",
    )
