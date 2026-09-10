"""did_nostr -- a small, dependency-light reference implementation of Resolving
Architecture's DID design: secp256k1 / BIP-340 identities, Nostr-compatible
signed records, attestations as a decentralised replacement for NIP-05, and
guardian-based key recovery and rotation.

Spec: ``../DESIGN.md``. Conformance suite: ``did-vectors`` (vendored in
``tests/vectors``). Public domain (CC0 1.0).
"""

from __future__ import annotations

from .attestation import (
    AttestationInput,
    Claim,
    ParsedAttestation,
    create_attestation,
    is_expired,
    parse_attestation,
    revoke_attestation,
)
from .diddoc import did_document, multikey_to_xonly, xonly_to_multikey
from .event import (
    NostrEvent,
    VerifyResult,
    assert_valid,
    now,
    schnorr_sign_raw,
    schnorr_verify_raw,
    sign_event,
    verify_event,
)
from .keys import (
    Identity,
    did_to_hex,
    generate_identity,
    hex_to_did,
    hex_to_npub,
    is_valid_pubkey,
    normalize_pubkey,
    npub_to_hex,
    nsec_to_secret,
    public_key_from_secret,
    secret_to_nsec,
)
from .kinds import (
    CLAIM_ATTRIBUTES,
    DID_KINDS,
    KIND_GUARDIAN_SET,
    KIND_IDENTITY_ATTESTATION,
    KIND_ROTATION_ATTESTATION,
    KIND_ROTATION_CLAIM,
    METHODS,
    ROTATION_REASONS,
    validate_kind,
)
from .rotation import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    DEFAULT_COOLDOWN_SECONDS,
    EvaluateOptions,
    GuardianSetInput,
    RotationAttestationInput,
    RotationClaimInput,
    RotationVerdict,
    create_guardian_set,
    create_rotation_attestation,
    create_rotation_claim,
    evaluate_rotation,
    prev_sig,
)
from .serialize import (
    EventTemplate,
    compute_id,
    preimage_bytes,
    serialize_event,
    serialize_string,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # serialize
    "EventTemplate",
    "serialize_string",
    "serialize_event",
    "preimage_bytes",
    "compute_id",
    # keys
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
    # event
    "NostrEvent",
    "VerifyResult",
    "now",
    "sign_event",
    "verify_event",
    "assert_valid",
    "schnorr_sign_raw",
    "schnorr_verify_raw",
    # kinds
    "KIND_IDENTITY_ATTESTATION",
    "KIND_GUARDIAN_SET",
    "KIND_ROTATION_ATTESTATION",
    "KIND_ROTATION_CLAIM",
    "DID_KINDS",
    "METHODS",
    "CLAIM_ATTRIBUTES",
    "ROTATION_REASONS",
    "validate_kind",
    # attestation
    "Claim",
    "AttestationInput",
    "ParsedAttestation",
    "create_attestation",
    "revoke_attestation",
    "parse_attestation",
    "is_expired",
    # rotation
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
    # diddoc
    "xonly_to_multikey",
    "multikey_to_xonly",
    "did_document",
]
