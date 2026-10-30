"""Correlators, the web inspectors, and the endpoint inventory.

Runs against the five-exchange, three-host TLS fixture in
`tools/make_tls_pcap.py` — real TLS 1.3, real keylog. Skips if tshark is
absent.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from core.baseline import NullBaseline
from core.model import Context
from core.score import run
from ontology import ONTOLOGIES
from out.inventory import build_inventory, template_path
from out.sinks import write_json
from tools.make_tls_pcap import build_frames, capture_session, write_pcap

HAVE_TSHARK = shutil.which("tshark") is not None

THIRD_PARTY = "analytics.thirdparty-metrics.test"
PRIMARY = "api.target-practice.test"
AUTH_HOST = "auth.target-practice.test"


def _analyse(tmp: Path):
    from capture.tshark import HttpProfile, TsharkSource

    pcap, keylog = tmp / "tls.pcap", tmp / "keys.log"
    sessions = capture_session(keylog)
    assert sessions, "TLS handshakes produced no ciphertext"
    write_pcap(pcap, build_frames(sessions))

    source = TsharkSource(pcap, profile=HttpProfile(), keylog=keylog)
    series = list(group_into_series(source.observations(), min_observations=1))
    ctx = Context(
        now=max(s.end or 0.0 for s in series),
        baseline=NullBaseline(),
        mode="assisted",
    )
    findings, evidences = run(series, ONTOLOGIES, ctx)
    return findings, evidences, series


def _rule(findings, rule_id):
    return next((f for f in findings if f.rule_id == rule_id), None)


# --------------------------------------------------------------------------
# path templating
# --------------------------------------------------------------------------


def test_path_templating_distinguishes_identifier_kinds():
    """`{id}` must stay separate from `{uuid}` and `{opaque}` — only the
    numeric one implies enumerability, and conflating them would turn every
    REST API into an apparent IDOR finding."""
    assert template_path("/v2/users/4417/orders")[0] == "/v2/users/{id}/orders"
    assert template_path("/a/550e8400-e29b-41d4-a716-446655440000")[0] == "/a/{uuid}"
    assert template_path("/f/deadbeefcafebabe1234")[0] == "/f/{hash}"
    assert template_path("/static/app.min.js")[0] == "/static/app.min.js"
    assert template_path("/v2/orders")[0] == "/v2/orders"

    _, replaced = template_path("/v2/users/4417/orders")
    assert replaced == (("{id}", "4417"),)


def test_templating_reports_what_it_replaced():
    """Throwing the concrete value away would lose the enumeration signal."""
    template, replaced = template_path("/a/12/b/34")
    assert template == "/a/{id}/b/{id}"
    assert [v for _, v in replaced] == ["12", "34"]


# --------------------------------------------------------------------------
# correlation
# --------------------------------------------------------------------------


def test_credential_leak_to_third_party_is_critical():
    """The headline correlation finding: one bearer token, two registrable
    domains. Invisible to anything that looks at one request."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, _, _ = _analyse(Path(d))
        leak = _rule(findings, "http.auth.credential_sent_to_third_party")
        assert leak is not None, "cross-host credential leak not detected"
        assert leak.severity.value == "critical"
        assert leak.confidence >= 0.85

        facts = leak.evidence.by_name("auth.credential_reuse").facts
        # Attribution must name the host that SHOULD NOT have the credential.
        # An earlier tie-break blamed the legitimate API for leaking to the
        # analytics host — exactly backwards, and it passed a naive assertion
        # that only checked a finding existed.
        assert facts["received_by"] == THIRD_PARTY
        assert PRIMARY in facts["also_sent_to"]
        assert facts["domain_split"] == "different"


def test_leak_points_at_the_third_party_request():
    """The display filter must open the offending request, not the legitimate
    one."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, _, series = _analyse(Path(d))
        leak = _rule(findings, "http.auth.credential_sent_to_third_party")
        assert leak.channel.dims["host"] == THIRD_PARTY
        inspection = leak.evidence.by_name("auth.credential_reuse")
        assert inspection.display_filter() == "tcp.stream eq 3"


def test_first_party_sharing_is_not_critical():
    """A credential shared between hosts on one registrable domain is
    plumbing, not a leak. If this fires as CRITICAL the tool is unusable on
    any real multi-host application."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, evidences, _ = _analyse(Path(d))
        criticals = [
            f for f in findings
            if f.rule_id == "http.auth.credential_sent_to_third_party"
        ]
        # Exactly one leak in the fixture: the analytics host. The auth host
        # shares the apex domain with the API and must not be reported.
        assert len(criticals) == 1
        assert all(f.channel.dims["host"] == THIRD_PARTY for f in criticals)


def test_identifier_spray_is_reported_quietly():
    """A user id reaching an analytics host is a data flow, often intended.
    Reported, but never as a vulnerability."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, _, _ = _analyse(Path(d))
        spray = _rule(findings, "http.privacy.identifier_to_third_party")
        if spray is not None:
            assert spray.severity.value == "low"


# --------------------------------------------------------------------------
# web inspectors
# --------------------------------------------------------------------------


def test_cors_reflection_with_credentials_is_high():
    """Reflected Origin plus Allow-Credentials is the combination that lets
    an attacker page read authenticated responses. Either alone is benign."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, _, _ = _analyse(Path(d))
        cors = _rule(findings, "http.cors.credentialed_wildcard_or_reflection")
        assert cors is not None, "credentialed CORS reflection not detected"
        assert cors.severity.value == "high"

        facts = cors.evidence.by_name("web.cors").facts
        assert facts["allow_credentials"] == "true"
        assert facts["request_origin"] == "https://evil.example"
        assert "reflects the request Origin" in facts["issues"]

        # and the general permissive rule must be superseded
        assert _rule(findings, "http.cors.permissive_policy") is None


def test_secrets_in_response_body_detected_and_masked():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        findings, evidences, _ = _analyse(tmp)
        secret = _rule(findings, "http.disclosure.secret_in_response_body")
        assert secret is not None, "secret in response body not detected"
        assert secret.severity.value == "critical"

        inspection = secret.evidence.by_name("web.secrets_in_response")
        kinds = inspection.facts["kinds_found"]
        assert "Stripe live secret key" in kinds
        assert "AWS access key id" in kinds
        assert inspection.facts["internal_hosts"]

        # The planted secrets must not survive serialisation.
        out = tmp / "f.json"
        write_json(out, findings, evidences)
        text = out.read_text()
        for planted in ("sk_live_" + "51HxQpLMNopQrStUvWxYz0123456789abcdef",
                        "AKIAIOSFODNN7EXAMPLE"):
            assert planted not in text, f"LEAKED: {planted}"
        # ...but the classification does.
        assert "Stripe live secret key" in text


def test_oauth_implicit_flow_defects_detected():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, _, _ = _analyse(Path(d))
        oauth = _rule(findings, "http.oauth.weak_authorization_request")
        assert oauth is not None, "OAuth flow defects not detected"

        facts = oauth.evidence.by_name("web.oauth").facts
        assert facts["response_type"] == "token"
        assert facts["pkce"] == "absent"
        assert facts["state"] == "absent"
        assert "implicit/hybrid" in facts["issues"]
        assert "no state parameter" in facts["issues"]
        assert "admin" in facts["scopes"]


def test_oauth_detected_by_parameter_shape_not_just_path():
    """An authorization endpoint on a non-standard path must still be
    recognised — `response_type` + `client_id` is the real tell."""
    from core.model import Channel, Direction, Entity, Locus, Observation
    from inspectors.web import OAuthFlow

    obs = Observation(
        ts=0.0,
        channel=Channel(domain="http", dims={"host": "sso.example"},
                        initiator=Entity("ip", "10.0.0.1"),
                        responder=Entity("ip", "10.0.0.2")),
        direction=Direction.EGRESS,
        size=100,
        kind="http_request",
        attrs={
            "path": "/weird/custom/login-start",
            "query": "response_type=token&client_id=abc&redirect_uri=http://x/cb",
            "host": "sso.example",
        },
        locus=Locus("c.pcap", frames=(1,)),
    )
    ctx = Context(now=0.0)
    result = OAuthFlow().run(obs, ctx)
    assert result is not None
    assert "plaintext http" in result.facts["issues"]


def test_disclosure_headers_stay_below_every_threshold():
    """Version disclosure is inventory, not a finding. It must be recorded as
    evidence without producing a report line of its own."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, evidences, _ = _analyse(Path(d))
        recorded = any(
            i.name == "web.disclosure" for e in evidences for i in e.inspections
        )
        assert recorded, "disclosure headers were not recorded at all"
        assert not any("disclosure.header" in f.rule_id for f in findings)


# --------------------------------------------------------------------------
# inventory
# --------------------------------------------------------------------------


def test_inventory_maps_every_host_and_endpoint():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        _, _, series = _analyse(Path(d))
        inventory = build_inventory(series)

        assert set(inventory.hosts) == {PRIMARY, THIRD_PARTY, AUTH_HOST}
        assert inventory.endpoint_count == 5

        api = inventory.hosts[PRIMARY]
        assert set(api.endpoints) == {
            "/v2/account/profile", "/v2/users/{id}/orders", "/v2/orders",
        }
        assert api.endpoints["/v2/orders"].methods == {"POST"}
        assert api.endpoints["/v2/orders"].statuses == {"201"}
        assert api.endpoints["/v2/users/{id}/orders"].query_params == {"limit", "offset"}
        assert api.endpoints["/v2/users/{id}/orders"].identifiers["{id}"] == {"4417"}


def test_inventory_records_statuses_against_the_requesting_endpoint():
    """Responses must land on the endpoint that produced them. Without the
    request path carried forward, every status would attach to whatever the
    response frame happened to report."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        _, _, series = _analyse(Path(d))
        inventory = build_inventory(series)
        api = inventory.hosts[PRIMARY]
        assert api.endpoints["/v2/account/profile"].statuses == {"200"}
        assert api.endpoints["/v2/orders"].statuses == {"201"}
        assert inventory.hosts[AUTH_HOST].endpoints["/oauth/authorize"].statuses == {"302"}


def test_enumerable_needs_more_than_one_value():
    """One id in a path proves nothing — every REST route has one. Two
    adjacent values are what make enumeration plausible."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        _, _, series = _analyse(Path(d))
        inventory = build_inventory(series)
        endpoint = inventory.hosts[PRIMARY].endpoints["/v2/users/{id}/orders"]
        assert len(endpoint.identifiers["{id}"]) == 1
        assert not endpoint.enumerable, "flagged enumerable on a single value"

        endpoint.identifiers["{id}"].add("4418")
        assert endpoint.enumerable


def test_inventory_reaches_the_json_output():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        findings, evidences, series = _analyse(tmp)
        out = tmp / "f.json"
        write_json(out, findings, evidences, inventory=build_inventory(series))
        data = json.loads(out.read_text())

        assert data["inventory"]["endpoint_count"] == 5
        hosts = {h["host"] for h in data["inventory"]["hosts"]}
        assert hosts == {PRIMARY, THIRD_PARTY, AUTH_HOST}


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------


def test_correlation_runs_between_analysis_and_scoring():
    """A rule can require a correlation result, so scoring must wait for
    every channel to be analysed. If correlation ran per-channel the leak
    rule could never fire."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        findings, evidences, series = _analyse(Path(d))

        # The correlation result must be present in the evidence of the
        # channel it was attributed to, not just in the finding.
        third = next(
            e for e in evidences
            if e.channel.dims.get("host") == THIRD_PARTY
        )
        assert third.by_name("auth.credential_reuse") is not None

        # And absent from the primary host's evidence.
        primary = next(
            e for e in evidences if e.channel.dims.get("host") == PRIMARY
        )
        assert primary.by_name("auth.credential_reuse") is None


def test_score_series_alone_cannot_see_correlations():
    """`score_series` is the single-channel convenience; correlation findings
    are unavailable there by construction, and that must stay explicit."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from core.score import score_series

    with tempfile.TemporaryDirectory() as d:
        _, _, series = _analyse(Path(d))
        third = next(s for s in series if s.channel.dims.get("host") == THIRD_PARTY)
        ctx = Context(now=third.end or 0.0, baseline=NullBaseline(), mode="assisted")
        evidence, findings = score_series(third, ONTOLOGIES["http"], ctx)
        assert evidence.by_name("auth.credential_reuse") is None
        assert not any(
            f.rule_id == "http.auth.credential_sent_to_third_party" for f in findings
        )


def test_unknown_tshark_fields_are_dropped_not_fatal():
    """Field names are not stable across Wireshark releases. An unknown `-e`
    makes tshark exit 1 and kill the run — which happened with
    `http.origin`, and cost every finding in the capture."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    class BadProfile(HttpProfile):
        fields = HttpProfile.fields + ("http.definitely_not_a_real_field",)

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        pcap, keylog = tmp / "tls.pcap", tmp / "keys.log"
        write_pcap(pcap, build_frames(capture_session(keylog)))

        source = TsharkSource(pcap, profile=BadProfile(), keylog=keylog)
        obs = list(source.observations())
        assert obs, "a bogus field killed the whole capture"
        assert "http.definitely_not_a_real_field" in source.dropped_fields


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
    print(f"\n{len(tests) - failed}/{len(tests)} passed"
          + ("" if HAVE_TSHARK else "   (tshark absent: backend tests skipped)"))
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
