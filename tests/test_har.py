"""HAR import, and whether it agrees with the pcap path.

The central test here is `test_har_and_pcap_agree`. Both fixtures are built
from one exchange list: the pcap puts it through real TLS and a recording
relay, the HAR writes it the way a browser would. If the findings differ, a
capture plugin is leaking its format into the analysis — which is the one
thing the Observation boundary exists to prevent.
"""

from __future__ import annotations

import json
import shutil
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
from out.inventory import build_inventory
from out.sinks import write_json
from tools.make_har import build_har
from tools.make_tls_pcap import build_frames, capture_session, write_pcap

HAVE_TSHARK = shutil.which("tshark") is not None

PRIMARY = "api.target-practice.test"
THIRD_PARTY = "analytics.thirdparty-metrics.test"
AUTH_HOST = "auth.target-practice.test"


def _har(tmp: Path) -> Path:
    path = tmp / "session.har"
    path.write_text(json.dumps(build_har()))
    return path


def _analyse_har(tmp: Path):
    source = HarSource(_har(tmp))
    series = list(group_into_series(source.observations(), min_observations=1))
    ctx = Context(
        now=max(s.end or 0.0 for s in series),
        baseline=NullBaseline(),
        mode="assisted",
    )
    findings, evidences = run(series, ONTOLOGIES, ctx)
    return findings, evidences, series, source


def _analyse_pcap(tmp: Path):
    from capture.tshark import HttpProfile, TsharkSource

    pcap, keylog = tmp / "tls.pcap", tmp / "keys.log"
    write_pcap(pcap, build_frames(capture_session(keylog)))
    source = TsharkSource(pcap, profile=HttpProfile(), keylog=keylog)
    series = list(group_into_series(source.observations(), min_observations=1))
    ctx = Context(
        now=max(s.end or 0.0 for s in series),
        baseline=NullBaseline(),
        mode="assisted",
    )
    return run(series, ONTOLOGIES, ctx)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


def test_har_entries_become_request_response_pairs():
    with tempfile.TemporaryDirectory() as d:
        _, _, series, source = _analyse_har(Path(d))
        obs = [o for s in series for o in s.observations]
        assert {o.kind for o in obs} == {"http_request", "http_response"}

        # The fixture's last entry is a failed request with status 0. It must
        # yield a request and NO response — a phantom status-0 response would
        # invent an endpoint in the inventory and hand inspectors a message
        # that never existed.
        requests = [o for o in obs if o.kind == "http_request"]
        responses = [o for o in obs if o.kind == "http_response"]
        assert len(requests) == len(responses) + 1
        assert any(o.attrs["path"] == "/v2/never-answered" for o in requests)
        assert not any(
            o.attrs.get("request_path") == "/v2/never-answered" for o in responses
        )


def test_har_prefers_the_raw_set_cookie_header():
    """Cookie ATTRIBUTES are the finding. The fixture's structured `cookies`
    array drops Domain and SameSite, as real exporters do — so the parser
    must read the raw header or `CookieSecurity` loses its best signal."""
    with tempfile.TemporaryDirectory() as d:
        _, evidences, _, _ = _analyse_har(Path(d))
        cookie = next(
            i for e in evidences for i in e.inspections if i.name == "auth.cookie"
        )
        assert cookie.facts["cookie.domain"] == ".target-practice.test"
        assert "missing SameSite" in cookie.facts["cookie.flags"]


def test_har_loci_do_not_emit_a_wireshark_filter():
    """A HAR entry index is not a frame number. Emitting
    `frame.number == 4` would produce a filter that opens a capture and
    highlights an unrelated packet — wrong in the way the analyst trusts."""
    with tempfile.TemporaryDirectory() as d:
        findings, evidences, series, _ = _analyse_har(Path(d))
        assert findings
        for finding in findings:
            assert finding.display_filter is None
            assert finding.reference and "entry" in finding.reference
        for one in series:
            assert one.display_filter() is None
            assert one.reference()


def test_har_timestamps_are_internally_consistent():
    """A response must land after its request, by the entry's elapsed time."""
    with tempfile.TemporaryDirectory() as d:
        _, _, series, _ = _analyse_har(Path(d))
        by_entry: dict = {}
        for one in series:
            for obs in one.observations:
                by_entry.setdefault(obs.attrs["stream"], {})[obs.kind] = obs.ts
        paired = [v for v in by_entry.values() if len(v) == 2]
        assert paired, "no request/response pairs found"
        for pair in paired:
            assert pair["http_response"] > pair["http_request"]


def test_malformed_har_fails_with_a_clear_message():
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "bad.har"
        bad.write_text('{"not": "a har"}')
        try:
            list(HarSource(bad).observations())
        except ValueError as exc:
            assert "log.entries" in str(exc)
        else:
            raise AssertionError("a HAR with no entries was accepted")

        worse = Path(d) / "worse.har"
        worse.write_text("this is not json")
        try:
            list(HarSource(worse).observations())
        except ValueError as exc:
            assert "not readable HAR" in str(exc)
        else:
            raise AssertionError("non-JSON was accepted")


# --------------------------------------------------------------------------
# the agreement test
# --------------------------------------------------------------------------


def test_har_and_pcap_agree():
    """THE ONE THAT MATTERS.

    Same exchanges, two completely different capture paths — real TLS through
    tshark, versus a browser-style HAR. The inspectors and correlators are
    unchanged between them. If the rule sets that fire differ, a capture
    plugin has leaked its format into the findings.
    """
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        har_findings, _, _, _ = _analyse_har(tmp)
        pcap_findings, _ = _analyse_pcap(tmp)

        har_rules = {f.rule_id for f in har_findings}
        pcap_rules = {f.rule_id for f in pcap_findings}
        assert har_rules == pcap_rules, (
            f"only in HAR: {har_rules - pcap_rules}; "
            f"only in pcap: {pcap_rules - har_rules}"
        )

        # Confidences must match too — a differing score means an inspector
        # saw different content, not merely a different container.
        har_scores = {
            (f.rule_id, f.channel.dims["host"]): round(f.confidence, 3)
            for f in har_findings
        }
        pcap_scores = {
            (f.rule_id, f.channel.dims["host"]): round(f.confidence, 3)
            for f in pcap_findings
        }
        assert har_scores == pcap_scores, (
            f"HAR {har_scores} != pcap {pcap_scores}"
        )


def test_har_finds_the_cross_host_leak():
    """Correlation works on HAR, which means it depends on the Observation
    model and not on packet structure."""
    with tempfile.TemporaryDirectory() as d:
        findings, _, _, _ = _analyse_har(Path(d))
        leak = next(
            (f for f in findings
             if f.rule_id == "http.auth.credential_sent_to_third_party"),
            None,
        )
        assert leak is not None, "cross-host leak missed on HAR input"
        assert leak.channel.dims["host"] == THIRD_PARTY
        facts = leak.evidence.by_name("auth.credential_reuse").facts
        assert facts["received_by"] == THIRD_PARTY


def test_har_inventory_matches_the_pcap_inventory():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from capture.tshark import HttpProfile, TsharkSource

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _, _, har_series, _ = _analyse_har(tmp)
        har_inv = build_inventory(har_series)

        pcap, keylog = tmp / "tls.pcap", tmp / "keys.log"
        write_pcap(pcap, build_frames(capture_session(keylog)))
        pcap_series = list(group_into_series(
            TsharkSource(pcap, profile=HttpProfile(), keylog=keylog).observations(),
            min_observations=1,
        ))
        pcap_inv = build_inventory(pcap_series)

        assert set(har_inv.hosts) == set(pcap_inv.hosts)
        for host in pcap_inv.hosts:
            pcap_endpoints = set(pcap_inv.hosts[host].endpoints)
            har_endpoints = set(har_inv.hosts[host].endpoints)
            # The HAR fixture adds one unanswered request the pcap lacks.
            assert pcap_endpoints <= har_endpoints, (
                f"{host}: pcap has endpoints the HAR missed: "
                f"{pcap_endpoints - har_endpoints}"
            )


def test_har_secrets_are_still_redacted():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        findings, evidences, series, _ = _analyse_har(tmp)
        out = tmp / "f.json"
        write_json(out, findings, evidences, inventory=build_inventory(series))
        text = out.read_text()
        for planted in (
            # assembled at runtime — see PLANTED_SECRETS in
            # test_http_inspection.py for why
            "sk_live_" + "8f3a2b1c9d4e5f6a7b8c9d0e",
            "sk_live_" + "51HxQpLMNopQrStUvWxYz0123456789abcdef",
            "AKIAIOSFODNN7EXAMPLE",
            "7f3a2b1c9d4e5f6a",
        ):
            assert planted not in text, f"LEAKED from HAR path: {planted}"


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
          + ("" if HAVE_TSHARK else "   (tshark absent: comparison tests skipped)"))
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
