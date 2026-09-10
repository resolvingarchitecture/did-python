"""End-to-end walkthrough of did-python. Run with:

    python examples/demo.py

It creates identities, has one vouch for another, produces the did:nostr view,
then loses a key and recovers it through guardians -- printing each signed event
so you can see exactly what goes on the wire.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from did_nostr import (  # noqa: E402
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
    evaluate_rotation,
    generate_identity,
    hex_to_did,
    hex_to_npub,
    parse_attestation,
    verify_event,
)


def rule(s: str) -> None:
    print("\n---- " + s + " " + "-" * max(0, 40 - len(s)))


def show(label: str, ev) -> None:
    v = verify_event(ev)
    status = "ok" if v.ok else f"FAIL step {v.step} ({v.reason})"
    print(f"{label}  [kind {ev.kind}]  verify: {status}")
    print(json.dumps(ev.to_dict()))


# 1. Identities
rule("identities")
alice = generate_identity()
bob = generate_identity()
print("alice  hex ", alice.pubkey)
print("       npub", hex_to_npub(alice.pubkey))
print("       did ", hex_to_did(alice.pubkey))
print("bob    hex ", bob.pubkey)

# 2. Attestation: bob vouches for alice's name, in person
rule("attestation (bob -> alice)")
attestation = create_attestation(
    AttestationInput(
        subject=alice.pubkey,
        claims=[Claim("name", "Alice"), Claim("nip05", "alice@example.com")],
        method="in-person",
    ),
    bob.secret_hex,
)
show("bob's attestation", attestation)
print("parsed:", parse_attestation(attestation))

# 3. The did:nostr view of alice
rule("did:nostr document for alice")
print(json.dumps(did_document(alice.pubkey, ["wss://relay.example.com"]), indent=2))

# 4. Alice designates guardians
rule("guardian set")
g1, g2, g3 = generate_identity(), generate_identity(), generate_identity()
t0 = 1_700_000_000  # pretend the set has been in place a long time
guardian_set = create_guardian_set(
    GuardianSetInput([g1.pubkey, g2.pubkey, g3.pubkey], 2, created_at=t0),
    alice.secret_hex,
)
show("alice's guardian set (M=2 of 3)", guardian_set)

# 5. Alice loses her key. A new key claims succession, two guardians endorse.
rule("recovery")
alice_new = generate_identity()
claim_at = t0 + DEFAULT_COOLDOWN_SECONDS + 86_400  # well past the cool-down
claim = create_rotation_claim(
    RotationClaimInput(alice.pubkey, "lost", created_at=claim_at), alice_new.secret_hex
)
endorse1 = create_rotation_attestation(
    RotationAttestationInput(alice.pubkey, alice_new.pubkey, "in-person", created_at=claim_at + 3600),
    g1.secret_hex,
)
endorse2 = create_rotation_attestation(
    RotationAttestationInput(alice.pubkey, alice_new.pubkey, "existing-channel", created_at=claim_at + 7200),
    g2.secret_hex,
)
show("rotation claim (signed by the new key)", claim)
show("guardian 1 endorses", endorse1)
show("guardian 2 endorses", endorse2)

verdict = evaluate_rotation([guardian_set, claim, endorse1, endorse2])
rule("verdict")
print(verdict)
if verdict.accepted:
    print(
        f"\nalice's identity is now {hex_to_npub(verdict.new)}\n"
        "(a client migrates follows, contacts and prior attestations, and shows the identity as rotated)"
    )
else:
    print("\nrotation NOT accepted")
