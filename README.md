# did-python

A small, dependency-light implementation of [Resolving
Architecture](https://resolvingarchitecture.io)'s DID design, ported from the
[`did-ts`](https://github.com/resolvingarchitecture/did-ts) reference:

- one **secp256k1 / BIP-340** keypair as an identity, with `hex` / `npub` /
  `nsec` / `did:nostr` encodings;
- **Nostr-compatible signed records** with the exact canonical serialisation that
  makes signatures reproduce across implementations;
- **attestations** — the `vouch` primitive, a decentralised replacement for
  NIP-05;
- **guardian-based key recovery and rotation**, including the normative
  acceptance rule;
- the thin **`did:nostr`** document view.

Spec: [`DESIGN.md`](https://github.com/resolvingarchitecture) (`../DESIGN.md` in
the DID workspace). Drafts: identity attestations, and social recovery + key
rotation, published on Nostr as long-form articles.

**Status:** `0.1.0`, pre-release. Kind numbers `30100`–`30103` are **provisional**
(`DESIGN.md` §8) and held in one module (`did_nostr.kinds`) so a reassignment is a
one-line change.

## Install

```sh
pip install did-nostr
```

Runtime dependencies, and nothing else:
[`coincurve`](https://github.com/ofek/coincurve) (libsecp256k1 bindings, BIP-340
Schnorr) and [`bech32`](https://pypi.org/project/bech32/) (NIP-19). No
hand-rolled cryptography.

## Use

```python
from did_nostr import (
    AttestationInput, Claim, GuardianSetInput, RotationClaimInput,
    RotationAttestationInput, create_attestation, create_guardian_set,
    create_rotation_attestation, create_rotation_claim, did_document,
    evaluate_rotation, generate_identity, verify_event,
)

# an identity is one keypair
alice = generate_identity()
bob = generate_identity()

# bob vouches for alice's name, having checked in person
attestation = create_attestation(
    AttestationInput(
        subject=alice.pubkey,
        claims=[Claim("name", "Alice")],
        method="in-person",
    ),
    bob.secret_hex,
)
assert verify_event(attestation).ok

# the did:nostr view, produced offline from the public key alone
did_document(alice.pubkey)

# alice names guardians, then recovers to a new key when the old one is lost
guardian_set = create_guardian_set(
    GuardianSetInput([g1.pubkey, g2.pubkey, g3.pubkey], threshold=2), alice.secret_hex
)
claim = create_rotation_claim(
    RotationClaimInput(alice.pubkey, "lost"), alice_new.secret_hex
)
e1 = create_rotation_attestation(
    RotationAttestationInput(alice.pubkey, alice_new.pubkey, "in-person"), g1.secret_hex
)
e2 = create_rotation_attestation(
    RotationAttestationInput(alice.pubkey, alice_new.pubkey, "existing-channel"), g2.secret_hex
)

evaluate_rotation([guardian_set, claim, e1, e2])
# RotationVerdict(accepted=True, reason='...', new='<alice_new.pubkey>', old='<alice.pubkey>')
```

A full end-to-end walkthrough that prints every signed event:

```sh
python examples/demo.py
```

## API

| Area | Exports |
|------|---------|
| Keys & encodings | `generate_identity`, `public_key_from_secret`, `is_valid_pubkey`, `hex_to_npub` / `npub_to_hex`, `secret_to_nsec` / `nsec_to_secret`, `hex_to_did` / `did_to_hex`, `normalize_pubkey` |
| Serialisation | `serialize_event`, `serialize_string`, `preimage_bytes`, `compute_id` |
| Events | `sign_event`, `verify_event` (four-step order, returns the failing step), `assert_valid`, `schnorr_sign_raw` / `schnorr_verify_raw` |
| Kinds | `KIND_IDENTITY_ATTESTATION` … `KIND_ROTATION_CLAIM`, `DID_KINDS`, `METHODS`, `ROTATION_REASONS`, `validate_kind` |
| Attestations | `create_attestation`, `revoke_attestation`, `parse_attestation`, `is_expired` |
| Rotation | `create_guardian_set`, `create_rotation_claim`, `create_rotation_attestation`, `prev_sig`, `evaluate_rotation`, `DEFAULT_COOLDOWN_SECONDS` |
| `did:nostr` | `did_document`, `xonly_to_multikey`, `multikey_to_xonly` |

`sign_event` uses BIP-340 `aux_rand = 0` by default, so events are byte-for-byte
reproducible (this is how the vectors are generated); pass your own randomness if
you prefer. Verification never depends on how a signature was produced.

`nsec` export lives behind `secret_to_nsec` and is never called by the library
itself — per `DESIGN.md` §6.3 a caller MUST gate it behind an explicit,
separately-confirmed user action and MUST NOT surface `nsec` incidentally.

## Conformance

The [`did-vectors`](https://github.com/resolvingarchitecture/did-vectors)
conformance suite is vendored (copied, not a submodule) at
[`tests/vectors/`](tests/vectors/) and re-copied when it changes upstream. The
test suite:

- checks canonical serialisation, `id` derivation and signature reproduction
  against `events.json`;
- verifies every valid vector and rejects every invalid one **at the stated
  step**;
- runs the rotation acceptance rule against all 19 scenarios in `rotation.json`;
- cross-verifies did-python output with **`pynostr`**, unmodified, so
  "Nostr-compatible" is checked and not just asserted.

```sh
pip install -e ".[test]"
pytest
python examples/demo.py
```

## License

**Public domain** — [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/),
see [`LICENSE`](LICENSE). Copy any of it into any implementation, ship it with a
NIP, no attribution required.
