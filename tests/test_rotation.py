"""Conformance against did-vectors/rotation.json -- the guardian rotation
acceptance rule (DESIGN.md §4.3). Vendored copy in tests/vectors/.
"""

import json
from pathlib import Path

import pytest

from did_nostr import EvaluateOptions, NostrEvent, evaluate_rotation, verify_event

VECTORS = json.loads((Path(__file__).parent / "vectors" / "rotation.json").read_text())
COOLDOWN = VECTORS["cooldown_seconds"]


def _events(case) -> list:
    return [NostrEvent.from_dict(e) for e in case["events"]]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_every_event_in_every_case_is_well_formed(case):
    for ev in _events(case):
        r = verify_event(ev)
        assert r.ok, f"event {ev.id} failed at step {r.step}: {r.reason}"


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_acceptance_rule_reaches_stated_verdict(case):
    verdict = evaluate_rotation(
        _events(case), EvaluateOptions(cooldown_seconds=COOLDOWN)
    )
    assert verdict.accepted == case["accept"], verdict.reason
    if case["accept"]:
        assert verdict.new, "an accepted rotation names a successor key"
        assert verdict.old, "an accepted rotation names the old key"
