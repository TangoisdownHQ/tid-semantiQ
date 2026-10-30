"""Refresh-token rotation.

Two findings of different evidential strength, and the distinction is the
point:

    not_rotated   the response did not carry a new token — good evidence,
                  still an inference about what the server will accept
    replayed      the same token was accepted twice — an observation about
                  what the server DID accept

The replay rule supersedes the other, so a capture that proves the behaviour
does not also report the inference.

`test_rotating_server_is_silent` and `test_rejected_refresh_is_not_judged`
are the negative tests that keep this usable: correct rotation must produce
nothing, and a failed refresh says nothing about rotation at all.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.har import HarSource
from core.baseline import NullBaseline
from core.model import Context
from core.score import run
from correlators.oauth import LONG_LIVED_ACCESS_S, _form_or_json
from ontology import ONTOLOGIES
from out.sinks import write_json
from tools.make_har import build_refresh_har

HOST = "auth.target-practice.test"
PLANTED_TOKEN = "rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0"


def _analyse(har: dict):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.har"
        path.write_text(json.dumps(har))
        series = list(group_into_series(
            HarSource(path).observations(), min_observations=1
        ))
        ctx = Context(
            now=max(s.end or 0.0 for s in series),
            baseline=NullBaseline(), mode="assisted",
        )
        return run(series, ONTOLOGIES, ctx)


def _rule(findings, rule_id):
    return next((f for f in findings if f.rule_id == rule_id), None)


def _inspection(evidences, name):
    for evidence in evidences:
        result = evidence.by_name(name)
        if result is not None:
            return result
    return None


# --------------------------------------------------------------------------
# body parsing
# --------------------------------------------------------------------------


def test_reads_form_and_json_bodies():
    """Token endpoints take form encoding, but clients in the wild send JSON
    to the same endpoint, so both must parse."""
    form = _form_or_json("grant_type=refresh_token&refresh_token=abc123")
    assert form["grant_type"] == "refresh_token"
    assert form["refresh_token"] == "abc123"

    as_json = _form_or_json('{"grant_type": "refresh_token", "expires_in": 900}')
    assert as_json["grant_type"] == "refresh_token"
    assert as_json["expires_in"] == "900"

    assert _form_or_json("") == {}
    assert _form_or_json("{not json") == {}
    assert _form_or_json("[1,2,3]") == {}


# --------------------------------------------------------------------------
# negative tests
# --------------------------------------------------------------------------


def test_rotating_server_is_silent():
    """Correct behaviour must produce nothing, or the finding is worthless."""
    findings, _ = _analyse(build_refresh_har(rotates=True))
    assert not [
        f for f in findings if f.rule_id.startswith("http.oauth.refresh")
    ], [f.rule_id for f in findings]


def test_rejected_refresh_is_not_judged():
    """A 400 means the server was never asked to issue a replacement, so the
    exchange says nothing about rotation. Judging it would report every
    client that holds an expired token."""
    findings, evidences = _analyse(build_refresh_har(rejected=True))
    assert not [
        f for f in findings if f.rule_id.startswith("http.oauth.refresh")
    ]
    assert _inspection(evidences, "oauth.refresh_rotation.not_rotated") is None
    assert _inspection(evidences, "oauth.refresh_rotation.replayed") is None


def test_other_grant_types_are_ignored():
    """A token endpoint also serves authorization_code and
    client_credentials, and neither says anything about refresh rotation."""
    har = build_refresh_har(rotates=False)
    for entry in har["log"]["entries"]:
        entry["request"]["postData"]["text"] = (
            "grant_type=authorization_code&code=xyz"
            "&refresh_token=rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0"
        )
    findings, evidences = _analyse(har)
    assert not [
        f for f in findings if f.rule_id.startswith("http.oauth.refresh")
    ]
    assert _inspection(evidences, "oauth.refresh_rotation.replayed") is None


def test_short_tokens_are_not_compared():
    """A placeholder value is not a credential, and comparing it would make
    every test harness look vulnerable."""
    har = build_refresh_har(rotates=False)
    for entry in har["log"]["entries"]:
        entry["request"]["postData"]["text"] = (
            "grant_type=refresh_token&refresh_token=short"
        )
    findings, _ = _analyse(har)
    assert not [
        f for f in findings if f.rule_id.startswith("http.oauth.refresh")
    ]


def test_a_single_refresh_cannot_prove_replay():
    """One use is not a replay. The weaker rule may still fire, but the
    strong one must not."""
    findings, _ = _analyse(build_refresh_har(rotates=False, refreshes=1))
    assert _rule(findings, "http.oauth.refresh_token_replayed") is None


# --------------------------------------------------------------------------
# positive tests
# --------------------------------------------------------------------------


def test_replayed_token_is_the_strong_finding():
    findings, _ = _analyse(
        build_refresh_har(rotates=False, replay_same_token=True, refreshes=4)
    )
    replayed = _rule(findings, "http.oauth.refresh_token_replayed")
    assert replayed is not None, [f.rule_id for f in findings]
    assert replayed.severity.value == "high"

    facts = replayed.evidence.by_name("oauth.refresh_rotation.replayed").facts
    assert int(facts["successful_uses"]) == 4
    assert facts["host"] == HOST
    notes = " ".join(
        replayed.evidence.by_name("oauth.refresh_rotation.replayed").notes
    )
    assert "observed behaviour, not an inference" in notes


def test_replay_supersedes_the_inference():
    """A capture that PROVES the behaviour should not also report the weaker
    inference about it."""
    findings, _ = _analyse(
        build_refresh_har(rotates=False, replay_same_token=True)
    )
    rules = {f.rule_id for f in findings}
    assert "http.oauth.refresh_token_replayed" in rules
    assert "http.oauth.refresh_token_not_rotated" not in rules


def test_missing_refresh_token_in_response_counts_as_no_rotation():
    """The other way servers get this wrong: the response omits
    `refresh_token` entirely, so the one the client already holds stays
    valid."""
    findings, evidences = _analyse(build_refresh_har(rotates=False))
    result = _inspection(evidences, "oauth.refresh_rotation.not_rotated")
    assert result is not None
    detail = result.facts["detail"]
    assert "no refresh token at all" in detail or "SAME refresh token" in detail
    assert int(result.facts["without_rotation"]) >= 1


def test_more_than_one_refresh_always_becomes_a_replay():
    """Worth stating, because it bounds where the weaker rule applies.

    A server that does not rotate hands back the same token, so the client
    presents that same token again next time — and no-rotation across two or
    more refreshes is therefore ALWAYS observable as a replay. The inference
    rule only ever applies to a capture holding a single exchange.
    """
    multi, _ = _analyse(build_refresh_har(rotates=False, refreshes=3))
    assert _rule(multi, "http.oauth.refresh_token_replayed") is not None
    assert _rule(multi, "http.oauth.refresh_token_not_rotated") is None

    single, _ = _analyse(build_refresh_har(rotates=False, refreshes=1))
    assert _rule(single, "http.oauth.refresh_token_replayed") is None
    assert _rule(single, "http.oauth.refresh_token_not_rotated") is not None


def test_long_lived_access_token_boosts_but_does_not_fire_alone():
    """A long `expires_in` is a design choice, not a defect. It compounds a
    missing rotation and must not stand on its own.

    Uses a single refresh, because with more than one the replay rule
    supersedes the rule being boosted — see the test above.
    """
    plain, _ = _analyse(
        build_refresh_har(rotates=False, refreshes=1, expires_in=900)
    )
    compounded, evidences = _analyse(
        build_refresh_har(rotates=False, refreshes=1,
                          expires_in=LONG_LIVED_ACCESS_S * 2)
    )

    a = _rule(plain, "http.oauth.refresh_token_not_rotated")
    b = _rule(compounded, "http.oauth.refresh_token_not_rotated")
    assert a is not None and b is not None
    assert b.confidence > a.confidence, "the boost did not apply"

    # ...and the lifetime alone produces no rule of its own.
    assert not any("long_lived" in f.rule_id for f in compounded)
    lifetime = _inspection(evidences, "oauth.refresh_rotation.long_lived_access")
    assert lifetime is not None
    assert float(lifetime.facts["expires_in_hours"]) >= 24


def test_rotating_server_with_long_access_tokens_stays_silent():
    """The boost must not resurrect a finding whose requirement failed."""
    findings, _ = _analyse(
        build_refresh_har(rotates=True, expires_in=LONG_LIVED_ACCESS_S * 2)
    )
    assert not [
        f for f in findings if f.rule_id.startswith("http.oauth.refresh")
    ]


def test_tokens_are_redacted():
    with tempfile.TemporaryDirectory() as d:
        har = build_refresh_har(rotates=False, replay_same_token=True)
        findings, evidences = _analyse(har)
        out = Path(d) / "f.json"
        write_json(out, findings, evidences)
        text = out.read_text()
        assert PLANTED_TOKEN not in text, "refresh token leaked"
        # ...but the finding survives.
        assert "cwe:613" in text
        assert "successful_uses" in text


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
