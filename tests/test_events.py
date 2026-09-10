"""Conformance against did-vectors/events.json -- the interoperability contract
(DESIGN.md §2.3). Vendored copy in tests/vectors/.
"""

import json
from pathlib import Path

import pytest

from did_nostr import (
    EventTemplate,
    NostrEvent,
    compute_id,
    serialize_event,
    sign_event,
    verify_event,
)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "events.json").read_text())
SEC_BY_PUB = {k["pub"]: k["sec"] for k in VECTORS["keys"].values()}


def _template(inp: dict) -> EventTemplate:
    return EventTemplate(
        pubkey=inp["pubkey"],
        created_at=inp["created_at"],
        kind=inp["kind"],
        tags=[list(t) for t in inp["tags"]],
        content=inp["content"],
    )


@pytest.mark.parametrize("case", VECTORS["serialization"], ids=lambda c: c["name"])
def test_canonical_serialisation_edge_cases(case):
    t = _template(case["input"])
    preimage = serialize_event(t)
    assert preimage == case["preimage"]
    assert len(preimage.encode("utf-8")) == case["preimage_utf8_bytes"]
    assert compute_id(t) == case["id"]


@pytest.mark.parametrize("case", VECTORS["valid_events"], ids=lambda c: c["name"])
def test_valid_events_verify(case):
    r = verify_event(NostrEvent.from_dict(case["event"]))
    assert r.ok, f"expected valid, got step {r.step}: {r.reason}"


@pytest.mark.parametrize(
    "case",
    [c for c in VECTORS["valid_events"] if c["event"]["pubkey"] in SEC_BY_PUB],
    ids=lambda c: c["name"],
)
def test_valid_event_signatures_reproduce_with_zero_aux(case):
    ev = case["event"]
    re_signed = sign_event(
        {
            "created_at": ev["created_at"],
            "kind": ev["kind"],
            "tags": ev["tags"],
            "content": ev["content"],
        },
        SEC_BY_PUB[ev["pubkey"]],
    )
    assert re_signed.id == ev["id"]
    assert re_signed.sig == ev["sig"]


@pytest.mark.parametrize("case", VECTORS["invalid_events"], ids=lambda c: c["name"])
def test_invalid_events_rejected_at_stated_step(case):
    r = verify_event(NostrEvent.from_dict(case["event"]))
    assert not r.ok, "expected rejection"
    assert r.step == case["fails_step"], f"expected failure at step {case['fails_step']}, got {r.step}"
