"""Session fixation, and the session-identifier-in-URL vector.

Comparing two cookie values is trivial; deciding that authentication happened
is a heuristic, and a wrong boundary produces a confident finding about
nothing. The negative tests are therefore about the boundary:

  test_failed_login_is_not_a_boundary     a 401 rotates nothing, so treating
                                          it as a boundary would report
                                          fixation on every application that
                                          correctly rejects a bad password
  test_get_request_is_not_a_boundary      a GET does not authenticate
  test_capture_ending_at_login_declines   "could not observe rotation" is not
                                          "rotation did not happen"
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
from ontology import ONTOLOGIES
from out import collect_advisories
from out.sinks import write_json
from tools.make_har import build_fixation_har

PRE_VALUE = "AAAAAAAAAAAAAAAA1111"
POST_VALUE = "BBBBBBBBBBBBBBBB2222"


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
# positive
# --------------------------------------------------------------------------


def test_non_rotating_session_is_detected():
    findings, evidences = _analyse(build_fixation_har(rotates=False))
    fixation = _rule(findings, "http.session.fixation")
    assert fixation is not None, "fixation not detected"
    assert fixation.severity.value == "high"
    assert fixation.confidence >= 0.85

    facts = fixation.evidence.by_name("auth.session_fixation").facts
    assert facts["cookie.name"] == "sessionid"
    assert facts["rotated"] == "no"
    assert facts["auth_status"] == "200"
    assert int(facts["requests_before"]) >= 1
    assert int(facts["requests_after"]) >= 1


def test_boundary_signal_is_reported():
    """A heuristic boundary must be visible, or the operator cannot check it."""
    findings, _ = _analyse(build_fixation_har(rotates=False))
    fixation = _rule(findings, "http.session.fixation")
    facts = fixation.evidence.by_name("auth.session_fixation").facts
    assert "/login" in facts["auth_signal"]
    assert "password field" in facts["auth_signal"]
    assert facts["auth_endpoint"].endswith("/login")

    notes = " ".join(fixation.evidence.by_name("auth.session_fixation").notes)
    assert "heuristic" in notes


def test_reissuing_the_same_value_scores_higher():
    """A server that calls Set-Cookie after login and writes the SAME value
    is not missing a rotation step — its generator does not rotate. Worth
    distinguishing, because the fix is different."""
    plain, _ = _analyse(build_fixation_har(rotates=False))
    reissued, evidences = _analyse(
        build_fixation_har(rotates=False, reissue_same=True)
    )

    a = _rule(plain, "http.session.fixation")
    b = _rule(reissued, "http.session.fixation")
    assert a is not None and b is not None
    assert b.confidence > a.confidence

    facts = b.evidence.by_name("auth.session_fixation").facts
    assert facts["reissued_same_value"] == "yes"


# --------------------------------------------------------------------------
# negative — the boundary
# --------------------------------------------------------------------------


def test_rotating_session_is_not_reported():
    """The correct behaviour must be silent, or the finding is worthless."""
    findings, _ = _analyse(build_fixation_har(rotates=True))
    assert _rule(findings, "http.session.fixation") is None


def test_failed_login_is_not_a_boundary():
    """A 401 is not expected to rotate anything.

    Treating a failed authentication as a boundary would report fixation on
    every application that correctly rejects a bad password — which is to say
    on all of them.
    """
    findings, _ = _analyse(
        build_fixation_har(rotates=False, login_succeeds=False)
    )
    assert _rule(findings, "http.session.fixation") is None


def test_get_request_is_not_a_boundary():
    """A GET to /login is the login *form*, not an authentication."""
    har = build_fixation_har(rotates=False)
    for entry in har["log"]["entries"]:
        if entry["request"]["url"].endswith("/login"):
            entry["request"]["method"] = "GET"
            entry["request"].pop("postData", None)
    findings, _ = _analyse(har)
    assert _rule(findings, "http.session.fixation") is None


def test_no_login_at_all_is_not_reported():
    """A capture of ordinary browsing has no boundary to assess."""
    har = build_fixation_har(rotates=False)
    har["log"]["entries"] = [
        e for e in har["log"]["entries"]
        if not e["request"]["url"].endswith("/login")
    ]
    findings, _ = _analyse(har)
    assert _rule(findings, "http.session.fixation") is None


def test_capture_ending_at_login_declines_and_advises():
    """With no authenticated request, rotation cannot be observed. Declining
    is the only honest answer — the identifier may well rotate on the next
    request we did not capture."""
    findings, evidences = _analyse(
        build_fixation_har(rotates=False, requests_after=0)
    )
    assert _rule(findings, "http.session.fixation") is None

    result = _inspection(evidences, "auth.session_fixation")
    assert result is not None
    assert result.score == 0.0
    assert result.features["assessable"] == 0.0
    assert "rotation could not be observed" in result.facts["insufficient"]

    advisories = collect_advisories(evidences)
    assert any("rotation" in a for a in advisories)


def test_session_issued_only_after_login_is_not_fixation():
    """No pre-auth identifier means there was nothing to fix. This is the
    correct pattern and must be silent."""
    har = build_fixation_har(rotates=False)
    for entry in har["log"]["entries"]:
        # Strip every pre-login Cookie header so the client presents nothing
        # until the server issues one.
        if entry["request"]["url"].endswith(("/", "/catalog")):
            entry["request"]["headers"] = [
                h for h in entry["request"]["headers"]
                if h["name"].lower() != "cookie"
            ]
    findings, _ = _analyse(har)
    assert _rule(findings, "http.session.fixation") is None


def test_csrf_token_not_rotating_is_not_session_fixation():
    """A non-session cookie that fails to rotate is a different and lesser
    finding. Treating every cookie as a session identifier would fire on
    almost every application."""
    har = build_fixation_har(rotates=True)
    for entry in har["log"]["entries"]:
        headers = entry["request"]["headers"]
        for header in headers:
            if header["name"].lower() == "cookie":
                header["value"] += "; csrf_token=STATIC0000000000"
    findings, _ = _analyse(har)
    assert _rule(findings, "http.session.fixation") is None


# --------------------------------------------------------------------------
# the URL vector
# --------------------------------------------------------------------------


def test_session_id_in_url_is_detected():
    findings, _ = _analyse(
        build_fixation_har(rotates=True, session_in_url=True)
    )
    in_url = _rule(findings, "http.session.identifier_in_url")
    assert in_url is not None
    facts = in_url.evidence.by_name("auth.session_id_in_url").facts
    assert "sessionid" in facts["parameters"]


def test_url_vector_is_boosted_when_the_session_also_fixates():
    """A planted link plus a non-rotating session is account takeover from a
    single click, and must read as worse than either alone."""
    secure, _ = _analyse(build_fixation_har(rotates=True, session_in_url=True))
    both, _ = _analyse(build_fixation_har(rotates=False, session_in_url=True))

    a = _rule(secure, "http.session.identifier_in_url")
    b = _rule(both, "http.session.identifier_in_url")
    assert a is not None and b is not None
    assert b.confidence > a.confidence, "the chain was not escalated"
    assert _rule(both, "http.session.fixation") is not None


def test_short_url_values_are_not_session_ids():
    """`?sid=1` is a page parameter, not an identifier."""
    har = build_fixation_har(rotates=True)
    for entry in har["log"]["entries"]:
        if entry["request"]["url"].endswith("/catalog"):
            entry["request"]["url"] += "?sid=2"
    findings, _ = _analyse(har)
    assert _rule(findings, "http.session.identifier_in_url") is None


def test_path_embedded_jsessionid_is_detected():
    """The `;jsessionid=` form, which lives in the path rather than the query."""
    har = build_fixation_har(rotates=True)
    for entry in har["log"]["entries"]:
        if entry["request"]["url"].endswith("/catalog"):
            entry["request"]["url"] += ";jsessionid=ABCDEF0123456789"
    findings, _ = _analyse(har)
    in_url = _rule(findings, "http.session.identifier_in_url")
    assert in_url is not None
    facts = in_url.evidence.by_name("auth.session_id_in_url").facts
    assert "jsessionid" in facts["parameters"].lower()


# --------------------------------------------------------------------------
# redaction
# --------------------------------------------------------------------------


def test_session_identifiers_are_redacted():
    with tempfile.TemporaryDirectory() as d:
        har = build_fixation_har(rotates=False, session_in_url=True)
        path = Path(d) / "x.har"
        path.write_text(json.dumps(har))
        series = list(group_into_series(
            HarSource(path).observations(), min_observations=1
        ))
        ctx = Context(now=max(s.end or 0.0 for s in series),
                      baseline=NullBaseline(), mode="assisted")
        findings, evidences = run(series, ONTOLOGIES, ctx)

        out = Path(d) / "f.json"
        write_json(out, findings, evidences)
        text = out.read_text()
        assert PRE_VALUE not in text, "session identifier leaked"
        # ...but the finding survives.
        assert "cwe:384" in text
        assert '"rotated": "no"' in text


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
