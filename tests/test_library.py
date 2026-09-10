"""Library-level round trips that do not depend on the shared vectors:
encodings, the attestation and rotation builders, and the did:nostr view.
"""

import re

import pytest

from did_nostr import (
    DEFAULT_COOLDOWN_SECONDS,
    AttestationInput,
    Claim,
    GuardianSetInput,
    RotationAttestationInput,
    RotationClaimInput,
    create_attestation,
    create_guardian_set,
    create_rotation_attestation,
    create_rotation_claim,
    did_document,
    did_to_hex,
    evaluate_rotation,
    generate_identity,
    hex_to_did,
    hex_to_npub,
    multikey_to_xonly,
    normalize_pubkey,
    npub_to_hex,
    nsec_to_secret,
    parse_attestation,
    public_key_from_secret,
    revoke_attestation,
    secret_to_nsec,
    verify_event,
    xonly_to_multikey,
)


def test_identity_generation_and_derivation_agree():
    ident = generate_identity()
    assert re.match(r"^[0-9a-f]{64}$", ident.pubkey)
    assert public_key_from_secret(ident.secret_hex) == ident.pubkey


def test_npub_nsec_did_round_trips():
    ident = generate_identity()
    assert npub_to_hex(hex_to_npub(ident.pubkey)) == ident.pubkey
    assert nsec_to_secret(secret_to_nsec(ident.secret_hex)) == ident.secret_hex
    assert did_to_hex(hex_to_did(ident.pubkey)) == ident.pubkey
    assert normalize_pubkey(hex_to_npub(ident.pubkey)) == ident.pubkey
    assert normalize_pubkey(ident.pubkey.upper()) == ident.pubkey


def test_npub_to_hex_rejects_an_nsec():
    ident = generate_identity()
    with pytest.raises(ValueError):
        npub_to_hex(secret_to_nsec(ident.secret_hex))


def test_attestation_builds_verifies_and_parses():
    attester = generate_identity()
    subject = generate_identity()
    ev = create_attestation(
        AttestationInput(
            subject=subject.pubkey,
            claims=[Claim("name", "alice"), Claim("nip05", "alice@example.com")],
            method="in-person",
        ),
        attester.secret_hex,
    )
    assert verify_event(ev).ok
    p = parse_attestation(ev)
    assert p.attester == attester.pubkey
    assert p.subject == subject.pubkey
    assert p.method == "in-person"
    assert len(p.claims) == 2


def test_revocation_verifies_and_carries_no_claims():
    attester = generate_identity()
    subject = generate_identity()
    ev = revoke_attestation(subject.pubkey, "key rotated", attester.secret_hex)
    assert verify_event(ev).ok
    assert parse_attestation(ev).revoked == "key rotated"
    assert parse_attestation(ev).claims == []


def test_attestation_needs_at_least_one_claim():
    a = generate_identity()
    with pytest.raises(ValueError):
        create_attestation(AttestationInput(subject=a.pubkey, claims=[], method="asserted"), a.secret_hex)


def test_guardian_rotation_happy_path_accepts_past_the_cooldown():
    old = generate_identity()
    nxt = generate_identity()
    g1, g2, g3 = generate_identity(), generate_identity(), generate_identity()

    t0 = 1_700_000_000
    claim_at = t0 + DEFAULT_COOLDOWN_SECONDS + 3600

    events = [
        create_guardian_set(
            GuardianSetInput([g1.pubkey, g2.pubkey, g3.pubkey], 2, created_at=t0),
            old.secret_hex,
        ),
        create_rotation_claim(
            RotationClaimInput(old.pubkey, "lost", created_at=claim_at), nxt.secret_hex
        ),
        create_rotation_attestation(
            RotationAttestationInput(old.pubkey, nxt.pubkey, "in-person", created_at=claim_at + 60),
            g1.secret_hex,
        ),
        create_rotation_attestation(
            RotationAttestationInput(old.pubkey, nxt.pubkey, "existing-channel", created_at=claim_at + 120),
            g2.secret_hex,
        ),
    ]
    for ev in events:
        assert verify_event(ev).ok

    verdict = evaluate_rotation(events)
    assert verdict.accepted, verdict.reason
    assert verdict.new == nxt.pubkey
    assert verdict.old == old.pubkey


def test_fresh_guardian_set_inside_cooldown_does_not_count():
    old = generate_identity()
    nxt = generate_identity()
    g1, g2 = generate_identity(), generate_identity()
    claim_at = 1_800_000_000
    events = [
        create_guardian_set(
            GuardianSetInput([g1.pubkey, g2.pubkey], 2, created_at=claim_at - 3600),
            old.secret_hex,
        ),
        create_rotation_claim(
            RotationClaimInput(old.pubkey, "compromised", created_at=claim_at), nxt.secret_hex
        ),
        create_rotation_attestation(
            RotationAttestationInput(old.pubkey, nxt.pubkey, "existing-channel", created_at=claim_at + 60),
            g1.secret_hex,
        ),
        create_rotation_attestation(
            RotationAttestationInput(old.pubkey, nxt.pubkey, "existing-channel", created_at=claim_at + 90),
            g2.secret_hex,
        ),
    ]
    assert evaluate_rotation(events).accepted is False


def test_self_authorised_rotation_via_prev_sig_needs_no_guardians():
    old = generate_identity()
    nxt = generate_identity()
    claim = create_rotation_claim(
        RotationClaimInput(old.pubkey, "planned", old_secret_hex_for_prev_sig=old.secret_hex),
        nxt.secret_hex,
    )
    assert verify_event(claim).ok
    verdict = evaluate_rotation([claim])
    assert verdict.accepted, verdict.reason
    assert verdict.new == nxt.pubkey


def test_did_nostr_document_and_multikey_round_trip():
    ident = generate_identity()
    doc = did_document(ident.pubkey, ["wss://relay.example"])
    assert doc["id"] == "did:nostr:" + ident.pubkey
    assert doc["type"] == "DIDNostr"
    assert doc["verificationMethod"][0]["publicKeyMultibase"] == "fe70102" + ident.pubkey
    assert multikey_to_xonly(xonly_to_multikey(ident.pubkey)) == ident.pubkey
    assert doc["authentication"][0] == "did:nostr:" + ident.pubkey + "#0"
    assert len(doc["service"]) == 1
