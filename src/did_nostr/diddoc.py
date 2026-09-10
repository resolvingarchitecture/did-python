"""``did:nostr`` compatibility (``DESIGN.md`` §5).

RA does not define a DID method. This produces the ``did:nostr`` *view* of a key
it already holds, offline, from the public key alone -- the draft's "minimal
resolution". No HTTP ``.well-known`` tier (§5.3): that reintroduces a domain as a
trust anchor, which §3 exists to remove.

The ``did:nostr`` method is an unratified community draft. Re-verify these
details against the current draft before relying on them.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .keys import normalize_pubkey

__all__ = ["xonly_to_multikey", "multikey_to_xonly", "did_document"]

_MULTIKEY = re.compile(r"^fe70102([0-9a-f]{64})$")


def xonly_to_multikey(pubkey_hex: str) -> str:
    """Multikey encoding of an x-only key (§5.2):

      1. x-only (32 bytes) -> compressed secp256k1 (33 bytes) by prepending 0x02
      2. prepend the multicodec varint for secp256k1-pub: 0xe7 0x01
      3. multibase base16-lower: prefix ``f``, then lowercase hex

    i.e. ``publicKeyMultibase`` = ``f`` + ``e701`` + ``02`` + ``<x-only hex>``.
    """
    return "fe70102" + normalize_pubkey(pubkey_hex)


def multikey_to_xonly(multikey: str) -> str:
    """Decode a Multikey string back to x-only hex, or raise if it is not the expected shape."""
    m = _MULTIKEY.match(multikey)
    if not m:
        raise ValueError("not an x-only secp256k1 Multikey (f e701 02 <hex>)")
    return m.group(1)


def did_document(pubkey: str, relays: Optional[List[str]] = None) -> Dict[str, Any]:
    """Produce the ``did:nostr`` document for a public key, offline. ``relays``,
    when non-empty, adds an OPTIONAL ``service`` entry ("enhanced resolution").
    """
    hex_pk = normalize_pubkey(pubkey)
    did = "did:nostr:" + hex_pk
    vm_id = did + "#0"
    doc: Dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "type": "DIDNostr",
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": xonly_to_multikey(hex_pk),
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
    }
    if relays:
        doc["service"] = [
            {
                "id": did + "#relays",
                "type": "NostrRelays",
                "serviceEndpoint": relays[0] if len(relays) == 1 else list(relays),
            }
        ]
    return doc
