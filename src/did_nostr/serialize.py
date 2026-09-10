"""Canonical NIP-01 / ``DESIGN.md`` §2.1 serialisation.

The signature preimage is the UTF-8 encoding of::

    [0,<pubkey>,<created_at>,<kind>,<tags>,<content>]

serialised as compact JSON with **no whitespace anywhere**. In strings, only the
seven escapes below are emitted; every other character, including all multi-byte
UTF-8, is written literally (no ``\\/``, no ``\\uXXXX``).

This is hand-rolled rather than delegated to :func:`json.dumps` on purpose: a
generic JSON encoder also escapes lone control characters as ``\\uXXXX``, which
the spec forbids. Getting this exactly right is what makes signatures reproduce
across the four language ports.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List

__all__ = [
    "EventTemplate",
    "serialize_string",
    "serialize_event",
    "preimage_bytes",
    "compute_id",
]

_ESCAPES = {
    0x22: '\\"',
    0x5C: "\\\\",
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
    0x08: "\\b",
    0x0C: "\\f",
}


@dataclass
class EventTemplate:
    """The unsigned fields of an event, in canonical order."""

    pubkey: str
    created_at: int
    kind: int
    tags: List[List[str]] = field(default_factory=list)
    content: str = ""


def serialize_string(s: str) -> str:
    """Serialise one JSON string with the seven allowed escapes and nothing else."""
    out = ['"']
    for ch in s:
        out.append(_ESCAPES.get(ord(ch), ch))
    out.append('"')
    return "".join(out)


def _serialize_int(n: int) -> str:
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError(f"expected an integer, got {n!r}")
    return str(n)


def _serialize_tags(tags: List[List[str]]) -> str:
    return "[" + ",".join(
        "[" + ",".join(serialize_string(x) for x in tag) + "]" for tag in tags
    ) + "]"


def serialize_event(ev: EventTemplate) -> str:
    """The exact string that gets hashed to produce the event ``id``."""
    return (
        "[0,"
        + serialize_string(ev.pubkey)
        + ","
        + _serialize_int(ev.created_at)
        + ","
        + _serialize_int(ev.kind)
        + ","
        + _serialize_tags(ev.tags)
        + ","
        + serialize_string(ev.content)
        + "]"
    )


def preimage_bytes(ev: EventTemplate) -> bytes:
    """UTF-8 bytes of the canonical preimage."""
    return serialize_event(ev).encode("utf-8")


def compute_id(ev: EventTemplate) -> str:
    """The event id: lowercase hex of sha256 over the canonical preimage."""
    return hashlib.sha256(preimage_bytes(ev)).hexdigest()
