"""Ecosystem check (DESIGN.md §10): an event produced by did-python MUST validate
in an unmodified third-party Nostr library. Here that library is ``pynostr``.

This is what "Nostr-compatible" has to mean in practice -- software that has
never heard of Resolving Architecture can still check the signature.
"""

import json
from pathlib import Path

import pytest

pynostr_event = pytest.importorskip("pynostr.event")
Event = pynostr_event.Event

from did_nostr import (  # noqa: E402
    AttestationInput,
    Claim,
    GuardianSetInput,
    RotationClaimInput,
    create_attestation,
    create_guardian_set,
    create_rotation_claim,
    generate_identity,
    sign_event,
)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "events.json").read_text())


def _accepts(event_dict: dict) -> bool:
    try:
        return bool(Event.from_dict(event_dict).verify())
    except Exception:  # a malformed event that makes the verifier throw is still a rejection
        return False


def test_did_python_events_verify_under_pynostr():
    alice = generate_identity()
    bob = generate_identity()

    note = sign_event(
        {"kind": 1, "content": "móving to a new 🔑", "tags": [["t", "did"]]},
        alice.secret_hex,
    )
    attestation = create_attestation(
        AttestationInput(
            subject=alice.pubkey,
            claims=[Claim("name", "alice")],
            method="in-person",
        ),
        bob.secret_hex,
    )
    gset = create_guardian_set(
        GuardianSetInput([generate_identity().pubkey, generate_identity().pubkey], 2),
        alice.secret_hex,
    )
    claim = create_rotation_claim(
        RotationClaimInput(alice.pubkey, "planned"), generate_identity().secret_hex
    )

    for ev in (note, attestation, gset, claim):
        assert _accepts(ev.to_dict()), f"pynostr rejected a did-python kind {ev.kind} event"


def test_shared_valid_events_verify_under_pynostr():
    for case in VECTORS["valid_events"]:
        assert _accepts(case["event"]), f"pynostr rejected vector {case['name']}"


def test_pynostr_also_rejects_the_any_invalid_events():
    for case in VECTORS["invalid_events"]:
        if case["rejected_by"] != "any":
            continue  # 'did'-only cases: a permissive verifier accepts them
        assert not _accepts(case["event"]), f"pynostr accepted {case['name']}"
