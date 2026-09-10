"""The identity primitive (``DESIGN.md`` §1): one secp256k1 keypair, x-only
public key per BIP-340, and its encodings.

  - lowercase hex (64 chars) -- canonical; the only form used in preimages
  - ``npub1...`` / ``nsec1...`` -- Bech32 (NIP-19), for display and export only
  - ``did:nostr:<hex>`` -- the W3C view (§5)

``coincurve`` (libsecp256k1 bindings) provides BIP-340 Schnorr; ``bech32``
provides Bech32. There is no hand-rolled elliptic-curve code here and there must
never be.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import bech32
from coincurve import PrivateKey, PublicKeyXOnly

__all__ = [
    "Identity",
    "is_valid_pubkey",
    "generate_identity",
    "public_key_from_secret",
    "hex_to_npub",
    "npub_to_hex",
    "secret_to_nsec",
    "nsec_to_secret",
    "normalize_pubkey",
    "hex_to_did",
    "did_to_hex",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Identity:
    """One identity: a 32-byte secret and its x-only public key, both lowercase hex."""

    #: 32-byte secret scalar, lowercase hex. Treat as sensitive -- see §6.3.
    secret_hex: str
    #: 32-byte x-only public key, lowercase hex. The canonical identifier.
    pubkey: str


def is_valid_pubkey(s: str) -> bool:
    """True if ``s`` is 64 lowercase hex chars over a valid x-only curve point."""
    if not _HEX64.match(s):
        return False
    try:
        PublicKeyXOnly(bytes.fromhex(s))
        return True
    except Exception:  # noqa: BLE001 - coincurve raises library-specific error types
        return False


def _pubkey_hex_from_secret_bytes(sk: bytes) -> str:
    return PublicKeyXOnly.from_secret(sk).format().hex()


def generate_identity() -> Identity:
    """Generate a fresh identity from the platform CSPRNG."""
    sk = PrivateKey()
    return Identity(sk.secret.hex(), _pubkey_hex_from_secret_bytes(sk.secret))


def public_key_from_secret(secret_hex: str) -> str:
    """Derive the x-only public key (lowercase hex) from a 32-byte secret hex."""
    if not _HEX64.match(secret_hex):
        raise ValueError("secret key must be 64 lowercase hex chars")
    return _pubkey_hex_from_secret_bytes(bytes.fromhex(secret_hex))


# --- encodings ---------------------------------------------------------------


def _bech32_encode(hrp: str, data: bytes) -> str:
    converted = bech32.convertbits(data, 8, 5)
    assert converted is not None
    return bech32.bech32_encode(hrp, converted)


def _bech32_decode(s: str, want: str) -> bytes:
    hrp, data = bech32.bech32_decode(s)
    if hrp is None or data is None:
        raise ValueError("not a valid bech32 string")
    if hrp != want:
        raise ValueError(f"expected an {want}, got {hrp}")
    decoded = bech32.convertbits(data, 5, 8, False)
    if decoded is None or len(decoded) != 32:
        raise ValueError(f"{want} does not decode to a 32-byte key")
    return bytes(decoded)


def hex_to_npub(pubkey_hex: str) -> str:
    """hex -> ``npub1...``"""
    if not _HEX64.match(pubkey_hex):
        raise ValueError("pubkey must be 64 lowercase hex chars")
    return _bech32_encode("npub", bytes.fromhex(pubkey_hex))


def npub_to_hex(npub: str) -> str:
    """``npub1...`` -> hex. Rejects any other prefix."""
    return _bech32_decode(npub, "npub").hex()


def secret_to_nsec(secret_hex: str) -> str:
    """secret hex -> ``nsec1...``.

    Per §1.1 / §6.3 an implementation MUST NOT surface ``nsec`` incidentally.
    This function exists so an export flow can call it deliberately; it is never
    used by the library itself and callers MUST gate it behind explicit
    confirmation.
    """
    if not _HEX64.match(secret_hex):
        raise ValueError("secret key must be 64 lowercase hex chars")
    return _bech32_encode("nsec", bytes.fromhex(secret_hex))


def nsec_to_secret(nsec: str) -> str:
    """``nsec1...`` -> secret hex."""
    return _bech32_decode(nsec, "nsec").hex()


def normalize_pubkey(value: str) -> str:
    """hex or ``npub1...`` -> canonical lowercase hex. Accepts what §1.1 says to accept."""
    s = value.strip()
    if s.startswith("npub1"):
        return npub_to_hex(s)
    if s.startswith("did:nostr:") and _HEX64.match(s[len("did:nostr:") :]):
        return s[len("did:nostr:") :]
    lower = s.lower()
    if not _HEX64.match(lower):
        raise ValueError("expected 64 hex chars or an npub")
    return lower


def hex_to_did(pubkey_hex: str) -> str:
    """hex -> ``did:nostr:<hex>`` (§5.1 -- hex, not npub)."""
    if not _HEX64.match(pubkey_hex):
        raise ValueError("pubkey must be 64 lowercase hex chars")
    return "did:nostr:" + pubkey_hex


def did_to_hex(did: str) -> str:
    """``did:nostr:<hex>`` -> hex."""
    m = re.match(r"^did:nostr:([0-9a-f]{64})$", did)
    if not m:
        raise ValueError("expected did:nostr:<64 lowercase hex>")
    return m.group(1)
