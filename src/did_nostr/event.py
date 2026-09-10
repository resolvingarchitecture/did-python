"""Signed records (``DESIGN.md`` §2): Nostr events with a BIP-340 Schnorr
signature, and the normative four-step verification order.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from coincurve import PrivateKey, PublicKeyXOnly

from .keys import is_valid_pubkey, public_key_from_secret
from .kinds import validate_kind
from .serialize import EventTemplate, compute_id

__all__ = [
    "NostrEvent",
    "VerifyResult",
    "now",
    "sign_event",
    "verify_event",
    "assert_valid",
    "schnorr_sign_raw",
    "schnorr_verify_raw",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_ZERO_AUX = bytes(32)


@dataclass
class NostrEvent:
    """A fully signed Nostr event."""

    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: List[List[str]]
    content: str
    sig: str

    # -- convenience readers --------------------------------------------------

    def tag(self, name: str) -> Optional[str]:
        """First value of the first tag named ``name``."""
        for t in self.tags:
            if t and t[0] == name:
                return t[1] if len(t) > 1 else None
        return None

    def tag_values(self, name: str) -> List[str]:
        """Second value of every tag named ``name``."""
        return [t[1] for t in self.tags if len(t) > 1 and t[0] == name]

    def has_tag(self, name: str) -> bool:
        return any(t and t[0] == name for t in self.tags)

    def template(self) -> EventTemplate:
        return EventTemplate(self.pubkey, self.created_at, self.kind, self.tags, self.content)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": [list(t) for t in self.tags],
            "content": self.content,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NostrEvent":
        return cls(
            id=d["id"],
            pubkey=d["pubkey"],
            created_at=d["created_at"],
            kind=d["kind"],
            tags=[list(t) for t in d.get("tags", [])],
            content=d.get("content", ""),
            sig=d["sig"],
        )


@dataclass
class VerifyResult:
    """Which verification step failed, and why."""

    ok: bool
    #: The verification step (1-4) that failed; ``None`` on success.
    step: Optional[int] = None
    reason: Optional[str] = None

    def __bool__(self) -> bool:  # so ``if verify_event(ev):`` reads naturally
        return self.ok


def now() -> int:
    """Current unix time in whole seconds."""
    return int(time.time())


def sign_event(
    ev: Dict[str, Any],
    secret_hex: str,
    aux_rand: Optional[bytes] = None,
) -> NostrEvent:
    """Sign an event with a 32-byte secret hex.

    ``aux_rand`` defaults to 32 zero bytes, which makes signatures byte-for-byte
    reproducible (this is how ``did-vectors`` is generated). Pass real randomness
    in production if you prefer; verification never depends on how a signature
    was produced.

    ``ev`` is a mapping with ``kind`` (required) and optional ``created_at``,
    ``tags`` and ``content``.
    """
    template = EventTemplate(
        pubkey=public_key_from_secret(secret_hex),
        created_at=ev.get("created_at") if ev.get("created_at") is not None else now(),
        kind=ev["kind"],
        tags=[list(t) for t in ev.get("tags") or []],
        content=ev.get("content") or "",
    )
    event_id = compute_id(template)
    sig = PrivateKey(bytes.fromhex(secret_hex)).sign_schnorr(
        bytes.fromhex(event_id), _ZERO_AUX if aux_rand is None else aux_rand
    )
    return NostrEvent(
        id=event_id,
        pubkey=template.pubkey,
        created_at=template.created_at,
        kind=template.kind,
        tags=template.tags,
        content=template.content,
        sig=sig.hex(),
    )


def verify_event(ev: NostrEvent) -> VerifyResult:
    """Verify an event against ``DESIGN.md`` §2.2. Steps run in order and the
    first failure is returned:

      1. ``pubkey`` is 64 lowercase hex over a valid x-only point
      2. the recomputed ``id`` equals the stated ``id`` (and the stated ``id`` is
         itself 64 lowercase hex)
      3. the Schnorr signature verifies over the 32 raw ``id`` bytes
      4. kind-specific validation (§3, §4)

    Step 2 is not optional: an event whose ``id`` does not match its content is
    malformed even if the signature verifies against the stated ``id``.
    """
    # Step 1
    if not isinstance(ev.pubkey, str) or not _HEX64.match(ev.pubkey):
        return VerifyResult(False, 1, "pubkey is not 64 lowercase hex chars")
    if not is_valid_pubkey(ev.pubkey):
        return VerifyResult(False, 1, "pubkey is not a valid x-only point")

    # Step 2
    if not isinstance(ev.id, str) or not _HEX64.match(ev.id):
        return VerifyResult(False, 2, "id is not 64 lowercase hex chars")
    recomputed = compute_id(ev.template())
    if recomputed != ev.id:
        return VerifyResult(False, 2, f"id mismatch: computed {recomputed}")

    # Step 3
    if not isinstance(ev.sig, str) or not _HEX128.match(ev.sig):
        return VerifyResult(False, 3, "sig is not 128 lowercase hex chars")
    if not schnorr_verify_raw(ev.sig, ev.id, ev.pubkey):
        return VerifyResult(False, 3, "Schnorr signature does not verify")

    # Step 4
    ok, reason = validate_kind(ev)
    if not ok:
        return VerifyResult(False, 4, reason)

    return VerifyResult(True)


def assert_valid(ev: NostrEvent) -> None:
    """Raise :class:`ValueError` with the failing step if verification fails."""
    r = verify_event(ev)
    if not r.ok:
        raise ValueError(f"event verification failed at step {r.step}: {r.reason}")


def schnorr_verify_raw(sig_hex: str, msg32_hex: str, pubkey_hex: str) -> bool:
    """BIP-340 verify of an arbitrary 32-byte message (used by ``prev-sig``, §4.2)."""
    if not (_HEX128.match(sig_hex) and _HEX64.match(msg32_hex) and _HEX64.match(pubkey_hex)):
        return False
    try:
        return PublicKeyXOnly(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(sig_hex), bytes.fromhex(msg32_hex)
        )
    except Exception:  # noqa: BLE001
        return False


def schnorr_sign_raw(
    msg32_hex: str, secret_hex: str, aux_rand: Optional[bytes] = None
) -> str:
    """BIP-340 sign of an arbitrary 32-byte message (used to build a ``prev-sig``)."""
    if not (_HEX64.match(msg32_hex) and _HEX64.match(secret_hex)):
        raise ValueError("message and secret key must each be 64 lowercase hex chars")
    return (
        PrivateKey(bytes.fromhex(secret_hex))
        .sign_schnorr(bytes.fromhex(msg32_hex), _ZERO_AUX if aux_rand is None else aux_rand)
        .hex()
    )
