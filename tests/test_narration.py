"""The narrator — reading a capture and saying what is in it.

This is the tool's core output and it shipped untested, which is the wrong
way round: the findings path had 228 tests guarding a feature that stays
silent on most captures, while the path that runs on every single capture
had none.

Two kinds of test live here, and the second kind is the important one.

ARITHMETIC. Percentages, shares and bucket counts have to reconcile with
the observations they were computed from. A narrator is a machine for
turning 30,000 observations into forty lines, and every one of those lines
is an opportunity to divide by the wrong denominator in a way no human
would ever catch by eye.

HONESTY INVARIANTS. A report that says less than it knows is a bug, and a
report that implies more than it measured is a worse one. So: a truncated
list must say it was truncated; a measurement from two samples must not
outrank the same measurement from two hundred; a claim about resolution
failure must count only lookups that were actually answered; and a secret
must not survive a round trip through the narrator. Each of those is a real
defect this project has shipped at least once.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.base import group_into_series
from capture.pcap import PcapSource
from core.model import (
    Channel,
    Direction,
    Entity,
    Evidence,
    Finding,
    Locus,
    Observation,
    Series,
    Severity,
)
from core.primitives.structure import FailureRate, _wilson_lower
from core.score import run as score_run
from core.suffixes import default_list
from out import narrate as narrator
from out.narrate import (
    _connections,
    _identity,
    _names,
    _timeline,
    narrate,
)
from out.report import _coalesce, _roster


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def _flat(text: str) -> str:
    """Collapse whitespace before asserting on prose.

    The interpretation section wraps at 70 columns, so an assertion on a
    phrase is really an assertion about where the wrap happened to fall —
    which would make every test here break the next time a sentence is
    reworded by a word or two. Assert on the sentence, not the layout.
    """
    return " ".join(text.split())


def _dns_series(
    zone: str,
    qnames,
    rcodes,
    client: str = "10.0.0.5",
    server: str = "10.0.0.1",
) -> Series:
    """A DNS channel with one query and one response per name.

    `rcodes` is parallel to `qnames`; None means the query went unanswered,
    which is the case the failure-rate denominator has to exclude.
    """
    channel = Channel(
        domain="dns",
        dims={"proto": "udp", "qtype": "A", "zone": zone},
        initiator=Entity("ip", client),
        responder=Entity("ip", server),
    )
    observations = []
    ts = 1_700_000_000.0
    for index, (qname, rcode) in enumerate(zip(qnames, rcodes)):
        observations.append(
            Observation(
                ts=ts + index * 1.0,
                channel=channel,
                direction=Direction.EGRESS,
                size=40,
                kind="dns_query",
                attrs={"qname": qname, "qtype": "A", "encrypted": False},
                locus=Locus(source="t.pcap", frames=(index * 2 + 1,)),
            )
        )
        if rcode is not None:
            observations.append(
                Observation(
                    ts=ts + index * 1.0 + 0.01,
                    channel=channel,
                    direction=Direction.INGRESS,
                    size=90,
                    kind="dns_response",
                    attrs={
                        "qname": qname,
                        "qtype": "A",
                        "encrypted": False,
                        "rcode": "3" if rcode == "NXDOMAIN" else "0",
                        "rcode_name": rcode,
                    },
                    locus=Locus(source="t.pcap", frames=(index * 2 + 2,)),
                )
            )
    return Series(channel, observations)


def _finding(rule_id: str, zone: str, confidence: float,
             client: str = "10.0.0.5") -> Finding:
    channel = Channel(
        domain="dns",
        dims={"proto": "udp", "qtype": "A", "zone": zone},
        initiator=Entity("ip", client),
        responder=Entity("ip", "10.0.0.1"),
    )
    return Finding(
        rule_id=rule_id,
        title="t",
        channel=channel,
        severity=Severity.INFO,
        confidence=confidence,
        evidence=Evidence(channel=channel, series_count=0,
                          window=(0.0, 0.0), results=(), inspections=()),
    )


# --------------------------------------------------------------------------
# FailureRate: the statistic the narrator's resolution claim rests on
# --------------------------------------------------------------------------


def test_failure_rate_denominator_excludes_unanswered_queries():
    """Unanswered queries must not count as successes.

    The alternative makes a channel look HEALTHIER the more of it goes
    missing, which inverts the signal. Here: 4 queries, 2 answered, both
    NXDOMAIN. The honest answer is 2/2 failed, not 2/4.
    """
    series = _dns_series(
        "x.test",
        ["a.x.test", "b.x.test", "c.x.test", "d.x.test"],
        ["NXDOMAIN", "NXDOMAIN", None, None],
    )
    primitive = FailureRate(
        attr="rcode_name", success_values=frozenset({"NOERROR"})
    )
    result = primitive.compute(series, _ctx())

    assert result.features["answered"] == 2.0, result.features
    assert result.features["failures"] == 2.0, result.features
    assert result.features["failure_share"] == 1.0, result.features


def test_failure_rate_declines_when_nothing_was_answered():
    """No replies means no opinion. A zero here would assert that nothing
    failed about a channel we never saw an answer on."""
    series = _dns_series("x.test", ["a.x.test", "b.x.test"], [None, None])
    primitive = FailureRate(
        attr="rcode_name", success_values=frozenset({"NOERROR"})
    )
    assert primitive.compute(series, _ctx()) is None


def test_small_sample_cannot_outrank_large_sample():
    """2/2 and 200/200 are both a 100% observed failure rate. Scoring the
    raw share would rank them identically and hand the loudest findings to
    the thinnest evidence."""
    small = _wilson_lower(2, 2, 1.96)
    large = _wilson_lower(200, 200, 1.96)
    assert small < 0.5 < large, (small, large)
    assert large > 0.97, large

    # Monotone in sample size at a fixed share — more evidence for the same
    # rate must never score lower.
    bounds = [_wilson_lower(int(0.9 * n), n, 1.96) for n in (10, 50, 200, 1000)]
    assert bounds == sorted(bounds), bounds


def test_unknown_rcode_counts_as_failure():
    """Listing the one success rather than the six known failures. An rcode
    this build has never heard of is certainly not a resolution that
    worked, and the registry has room to grow."""
    series = _dns_series(
        "x.test", ["a.x.test", "b.x.test"], ["NOERROR", "rcode 11"]
    )
    primitive = FailureRate(
        attr="rcode_name", success_values=frozenset({"NOERROR"})
    )
    result = primitive.compute(series, _ctx())
    assert result.features["failures"] == 1.0, result.features


def test_success_only_channel_scores_low():
    """The regression guard for the inverse mistake: a healthy channel must
    not score high just because the primitive ran."""
    series = _dns_series(
        "ok.test", [f"h{i}.ok.test" for i in range(20)], ["NOERROR"] * 20
    )
    primitive = FailureRate(
        attr="rcode_name", success_values=frozenset({"NOERROR"})
    )
    result = primitive.compute(series, _ctx())
    assert result.score < 0.05, result.score


# --------------------------------------------------------------------------
# the undelegated-TLD explanation
# --------------------------------------------------------------------------


def test_undelegated_tld_detection():
    """`public_suffix()` answers "a" for `ridemcts.a` via the PSL default
    rule — correct for the algorithm, useless for deciding whether the name
    could ever have resolved. `is_delegated` asks the other question."""
    psl = default_list()
    assert psl.is_delegated("www.ridemcts.com")
    assert psl.is_delegated("foo.co.uk")
    assert not psl.is_delegated("ridemcts.a")
    assert not psl.is_delegated("ridemcts.e")
    assert not psl.is_delegated("host.invalidtldthatwillneverexist")


def test_undelegated_detection_is_not_fooled_by_case_or_trailing_dot():
    psl = default_list()
    assert psl.is_delegated("WWW.RIDEMCTS.COM")
    assert psl.is_delegated("www.ridemcts.com.")


# --------------------------------------------------------------------------
# narration arithmetic
# --------------------------------------------------------------------------


def test_resolution_share_matches_the_observations():
    """The headline percentage has to reconcile with what was counted.

    18 NXDOMAIN and 2 NOERROR is 10% resolved. An off-by-one in the
    denominator would read 10.5% and nobody would notice by eye.
    """
    series = [
        _dns_series(
            "bad.test",
            [f"h{i}.bad.test" for i in range(18)],
            ["NXDOMAIN"] * 18,
        ),
        _dns_series("ok.test", ["a.ok.test", "b.ok.test"],
                    ["NOERROR", "NOERROR"]),
    ]
    text = narrate(series, [], source_name="t.pcap")

    flat = _flat(text)
    assert "2 of 20 answered lookups resolved (10.0%); 18 failed" in flat, flat
    assert "90% of answered DNS lookups failed (18 of 20" in flat, flat


def test_interpretation_names_the_undelegated_tlds():
    series = [
        _dns_series("ridemcts.a", [f"h{i}.ridemcts.a" for i in range(8)],
                    ["NXDOMAIN"] * 8),
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap"))
    assert "does not exist in the root zone (.a)" in flat, flat
    assert "search-domain list to an unqualified name" in flat, flat


def test_interpretation_reports_single_initiator():
    series = [_dns_series("x.test", ["a.x.test"] * 3, ["NOERROR"] * 3)]
    flat = _flat(narrate(series, [], source_name="t.pcap"))
    assert "A single host, 10.0.0.5, originated every exchange" in flat, flat
    assert "1 distinct address." in flat, flat


def test_interpretation_reports_multiple_initiators_with_a_share():
    series = [
        _dns_series("x.test", ["a.x.test"] * 9, ["NOERROR"] * 9,
                    client="10.0.0.5"),
        _dns_series("x.test", ["a.x.test"] * 1, ["NOERROR"] * 1,
                    client="10.0.0.6"),
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap"))
    assert "2 hosts originated traffic to 1 destination." in flat, flat
    assert "10.0.0.5 is the busiest, accounting for 90% of exchanges" in flat, flat


def test_narrate_accepts_a_generator_of_series():
    """`group_into_series` returns a generator and callers pass it straight
    through. Every section walks `series` independently, so without
    materialising it the first section consumed the capture and the rest
    narrated an empty one — silently, with the report still rendering."""
    def generate():
        yield _dns_series("x.test", [f"h{i}.x.test" for i in range(8)],
                          ["NXDOMAIN"] * 8)

    flat = _flat(narrate(generate(), [], source_name="t.pcap"))
    assert "8 channels" in flat or "1 channels" in flat, flat
    assert "NXDOMAIN" in flat, flat
    assert "TIMELINE" in flat, flat


def test_timeline_accounts_for_every_observation():
    """Bucket counts must sum to the total. A boundary slip either drops an
    observation or counts it twice, and the bar chart hides both."""
    series = [
        _dns_series("x.test", [f"h{i}.x.test" for i in range(40)],
                    ["NOERROR"] * 40),
    ]
    total = sum(one.count for one in series)
    lines = _timeline(series, 12)
    counted = 0
    for line in lines:
        if "exch" in line:
            counted += int(line.split("exch")[0].split()[-1].replace(",", ""))
    assert counted == total, (counted, total)


def test_timeline_is_omitted_for_an_instantaneous_capture():
    """A zero-length span has no timeline, and dividing by it would raise."""
    channel = Channel(
        domain="dns", dims={"proto": "udp", "zone": "x.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "10.0.0.1"),
    )
    same_ts = [
        Observation(ts=1_700_000_000.0, channel=channel,
                    direction=Direction.EGRESS, size=10, kind="dns_query",
                    attrs={"qname": "a.x.test"},
                    locus=Locus(source="t.pcap", frames=(n,)))
        for n in (1, 2, 3)
    ]
    assert _timeline([Series(channel, same_ts)], 12) == []


# --------------------------------------------------------------------------
# identity and naming
# --------------------------------------------------------------------------


def test_channel_identity_shows_behaviour_dims_not_transport_dims():
    """Every DNS row once read `10.0.0.5 → 10.0.0.1` and nothing else, so
    the five top-cadence channels were indistinguishable."""
    series = _dns_series("example.test", ["a.example.test"], ["NOERROR"])
    text = _identity(series.channel)

    assert "zone=example.test" in text, text
    assert "qtype=A" in text, text
    assert "proto=" not in text, text


def test_name_map_prefers_the_most_observed_name_for_a_shared_address():
    """CDN fronts serve many names from one address. The label is for
    reading, so the busiest name wins rather than whichever sorted first."""
    def tls(sni: str, count: int) -> Series:
        channel = Channel(
            domain="net",
            dims={"proto": "tcp", "dport": "443", "sni": sni},
            initiator=Entity("ip", "10.0.0.5"),
            responder=Entity("ip", "203.0.113.9"),
        )
        observations = [
            Observation(ts=1_700_000_000.0 + i, channel=channel,
                        direction=Direction.EGRESS, size=100,
                        kind="tcp_burst", attrs={"sni": sni, "encrypted": True},
                        locus=Locus(source="t.pcap", frames=(i + 1,)))
            for i in range(count)
        ]
        return Series(channel, observations)

    names = _names([tls("quiet.test", 2), tls("busy.test", 50)])
    assert names["203.0.113.9"] == "busy.test", names


# --------------------------------------------------------------------------
# honesty invariants
# --------------------------------------------------------------------------


def test_truncated_lists_say_they_were_truncated():
    """A truncated list that does not announce it reads as a complete one.

    30 zones against a 12-row section: the output must state the remainder
    rather than quietly showing the head.
    """
    series = [
        _dns_series(f"z{i}.test", [f"a.z{i}.test"] * 3, ["NOERROR"] * 3)
        for i in range(30)
    ]
    text = narrate(series, [], source_name="t.pcap", top_n=12)
    assert "more" in text, text
    assert "30 distinct" in text or "further" in text, text


def test_unmeasured_channels_are_reported_as_unmeasured():
    """"Nothing here" and "nothing measurable here" are different claims."""
    series = [_dns_series("x.test", ["a.x.test"], ["NOERROR"])]
    text = narrate(series, [], source_name="t.pcap")
    assert "NOT ASSESSED" in text, text
    assert "unexamined one" in text, text


def test_narrator_redacts_declared_secrets():
    """The terminal is an output like any other. A live token printed to
    stdout is leaked, and the narrator must honour the same redaction the
    findings report does."""
    from core.model import InspectionResult

    channel = Channel(
        domain="http", dims={"host": "api.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("host", "api.test"),
    )
    inspection = InspectionResult(
        name="auth.cookie_security",
        score=0.9,
        facts={"cookie.name": "session", "cookie.value": "SUPERSECRETVALUE"},
        secret_facts=("cookie.value",),
        occurrences=1,
    )
    evidence = Evidence(channel=channel, series_count=1,
                        window=(0.0, 1.0), results=(),
                        inspections=(inspection,))
    text = narrate([], [evidence], source_name="t.pcap")

    assert "SUPERSECRETVALUE" not in text, text
    assert "cookie.name" in text, text


def test_narration_runs_on_a_real_capture_and_fills_every_section():
    """End to end on a generated pcap, through the real decoder.

    The unit tests above build Series directly, which would not catch a
    parser that stopped emitting `rcode_name`.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "t.pcap"
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "make_test_pcap.py"),
             "--profile", "suspect", str(path)],
            check=True, capture_output=True, cwd=str(ROOT),
        )
        source = PcapSource(path)
        # list(): group_into_series yields, and score_run would otherwise
        # consume the generator before the narrator saw any of it.
        series = list(group_into_series(list(source.observations())))
        findings, evidences = score_run(series, _ontologies(), _ctx())
        text = narrate(series, evidences, findings,
                       stats=source.stats, source_name=path.name)

    for section in ("WHAT THIS CAPTURE SHOWS", "CAPTURE", "TIMELINE",
                    "CONVERSATIONS"):
        assert section in text, f"missing {section}\n{text}"
    assert "exchanges on" in text, text


def test_rcode_survives_the_real_decoder():
    """The parser was discarding the response code entirely, so no rule or
    narration could ever see it. This is the guard for that regression."""
    from capture.decode import dns_question

    # A minimal NXDOMAIN response: header with QR=1, RCODE=3, one question.
    message = (
        b"\x12\x34"          # id
        b"\x81\x83"          # flags: QR=1, RD, RA, RCODE=3
        b"\x00\x01"          # qdcount
        b"\x00\x00\x00\x00\x00\x00"
        b"\x03abc\x04test\x00"
        b"\x00\x01\x00\x01"  # A, IN
    )
    parsed = dns_question(message)
    assert parsed is not None
    qname, qtype, is_response, rcode = parsed
    assert (qname, qtype, is_response, rcode) == ("abc.test", "A", True, 3), parsed


# --------------------------------------------------------------------------
# report coalescing
# --------------------------------------------------------------------------


def test_many_findings_of_one_rule_on_one_host_collapse():
    """67 restatements of one misconfiguration is the alert fatigue this
    tool exists to avoid. The measurement stays per-channel; the report
    does not."""
    findings = [
        _finding("dns.resolution.mostly_failing_zone", f"z{i}.test", 0.9)
        for i in range(20)
    ]
    groups = _coalesce(findings)
    assert len(groups) == 1, groups
    lead, siblings = groups[0]
    assert len(siblings) == 19


def test_coalescing_keeps_the_loudest_finding_as_the_lead():
    findings = [
        _finding("r", "quiet.test", 0.70),
        _finding("r", "loud.test", 0.99),
        _finding("r", "mid.test", 0.85),
    ]
    (lead, siblings), = _coalesce(findings)
    assert lead.channel.dims["zone"] == "loud.test", lead.channel.dims


def test_two_findings_do_not_collapse():
    """A roster of two is indirection, not a summary."""
    findings = [_finding("r", "a.test", 0.9), _finding("r", "b.test", 0.9)]
    groups = _coalesce(findings)
    assert len(groups) == 2, groups
    assert all(not siblings for _lead, siblings in groups)


def test_different_hosts_never_collapse_together():
    """A host beaconing to twelve destinations must stay visible as twelve.
    Keyed on initiator, so separate originating hosts stay separate."""
    findings = [
        _finding("r", "z.test", 0.9, client=f"10.0.0.{i}") for i in range(5)
    ]
    groups = _coalesce(findings)
    assert len(groups) == 5, groups


def test_roster_announces_what_it_elided():
    findings = [_finding("r", f"z{i}.test", 0.9) for i in range(40)]
    (lead, siblings), = _coalesce(findings)
    text = "\n".join(_roster(siblings))
    assert "39 further channel(s)" in text, text
    assert "more" in text, text


# --------------------------------------------------------------------------
# per-entity dossiers
# --------------------------------------------------------------------------


def _tls_series(address: str, sni: str, port: str, count: int,
                client: str = "10.0.0.5") -> Series:
    # Labels derived the way the parser derives them, so a fixture cannot
    # disagree with the real capture path about whether an address is
    # private — which is exactly how a loopback test came to assert the
    # wrong thing.
    from capture.decode import is_private

    channel = Channel(
        domain="net",
        dims={"proto": "tcp", "dport": port, "sni": sni},
        initiator=Entity("ip", client, labels={"private": is_private(client)}),
        responder=Entity("ip", address,
                         labels={"private": is_private(address)}),
    )
    observations = [
        Observation(
            ts=1_700_000_000.0 + i,
            channel=channel,
            direction=Direction.EGRESS if i % 2 else Direction.INGRESS,
            size=100 if i % 2 else 900,
            kind="tcp_burst",
            attrs={"sni": sni, "encrypted": True,
                   "tls_fingerprint": "abc123", "dport": port},
            locus=Locus(source="t.pcap", frames=(i + 1,)),
        )
        for i in range(count)
    ]
    return Series(channel, observations)


def _udp_series(address: str, port: str, count: int) -> Series:
    """A non-DNS UDP channel — the one that carries a dport dim."""
    channel = Channel(
        domain="net",
        dims={"proto": "udp", "dport": port},
        initiator=Entity("ip", "10.0.0.5", labels={"private": True}),
        responder=Entity("ip", address, labels={"private": True}),
    )
    observations = [
        Observation(ts=1_700_000_000.0 + i, channel=channel,
                    direction=Direction.EGRESS, size=300,
                    kind="udp_datagram", attrs={"dport": port},
                    locus=Locus(source="t.pcap", frames=(i + 1,)))
        for i in range(count)
    ]
    return Series(channel, observations)


def test_endpoint_dossier_reports_every_known_fact():
    series = [_tls_series("203.0.113.9", "shop.test", "443", 20)]
    flat = _flat(narrate(series, [], source_name="t.pcap"))

    assert "ENDPOINT DETAIL" in flat, flat
    assert "203.0.113.9" in flat, flat
    assert "shop.test" in flat, flat
    # 203.0.113.0/24 is TEST-NET-3: Python calls it private because it is
    # not globally routable, but it is not a LAN either. The label says
    # which it actually is.
    assert "reserved for documentation" in flat, flat
    assert "reached by 10.0.0.5" in flat, flat
    assert "transport tcp/443" in flat, flat
    # "tls" is the negotiated version; the client fingerprint is "tls print".
    # Separate labels because they answer different questions — one is what
    # the server agreed to, the other is what library the client used.
    assert "tls print abc123" in flat, flat
    assert "20 exchanges" in flat, flat


def test_endpoint_dossier_lists_every_name_on_a_shared_address():
    """The ranked tables collapse a CDN address to one label. The dossier
    must not — an address genuinely serving several names is a fact, and
    discarding the others loses it."""
    series = [
        _tls_series("203.0.113.9", "one.test", "443", 10),
        _tls_series("203.0.113.9", "two.test", "443", 4),
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap"))
    assert "one.test" in flat, flat
    assert "two.test" in flat, flat


def test_transport_pairs_protocol_with_its_own_port():
    """The regression guard for a real defect.

    Protocols and ports were crossed rather than paired, so a resolver whose
    only dport-carrying channel was DHCP reported `udp/67` against all of
    its traffic — a confident claim about the wrong protocol. Here: 30 DNS
    exchanges with no dport dim and 2 DHCP exchanges with one. `udp/67`
    must not be attached to the 30.
    """
    series = [
        _dns_series("x.test", [f"h{i}.x.test" for i in range(15)],
                    ["NOERROR"] * 15, server="10.0.0.1"),
        _udp_series("10.0.0.1", "67", 2),
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap"))

    assert "udp/67 (2)" in flat, flat
    assert "udp/67 (30)" not in flat, flat
    assert "udp (30)" in flat, flat


def test_zone_dossier_separates_resolution_outcome_from_silence():
    """An unanswered query is not a failed one: nothing came back, so the
    resolver's opinion is unknown rather than negative. Conflating them
    would let a channel look worse the more of it went missing."""
    series = [
        _dns_series(
            "half.test",
            [f"h{i}.half.test" for i in range(6)],
            ["NXDOMAIN", "NXDOMAIN", "NOERROR", None, None, None],
        )
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap"))

    assert "DNS ZONE DETAIL" in flat, flat
    assert "1 of 3 answered lookups resolved (33.3%)" in flat, flat
    assert "3 queries drew no response" in flat, flat


def test_zone_dossier_says_when_nothing_was_answered_at_all():
    series = [_dns_series("quiet.test", ["a.quiet.test"] * 4, [None] * 4)]
    flat = _flat(narrate(series, [], source_name="t.pcap"))
    assert "no responses observed" in flat, flat
    assert "does not show whether these resolved" in flat, flat


def test_zone_dossier_flags_an_undelegated_tld_per_zone():
    """Stated per zone as well as in the prose: it is the single fact that
    explains every failed lookup in the block beneath it."""
    series = [
        _dns_series("ridemcts.a", ["ridemcts.a"] * 8, ["NXDOMAIN"] * 8)
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap"))
    assert ".a is not a delegated top-level domain" in flat, flat


def test_delegated_zone_is_not_flagged():
    """The inverse guard: a normal zone must not be accused of not existing."""
    series = [
        _dns_series("example.com", ["www.example.com"] * 8, ["NOERROR"] * 8)
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap"))
    assert "not a delegated top-level domain" not in flat, flat


def test_dossiers_announce_how_many_they_did_not_detail():
    """A dossier section that silently shows the top few reads as a complete
    inventory of the capture's endpoints."""
    series = [
        _tls_series(f"203.0.113.{i}", f"h{i}.test", "443", 5)
        for i in range(20)
    ]
    flat = _flat(narrate(series, [], source_name="t.pcap", top_n=3))
    assert "top 3 of 20 by volume" in flat, flat
    assert "17 further endpoint(s) not detailed" in flat, flat


def test_dossier_measurements_come_from_the_evidence():
    """The `measured` line has to read real primitive scores, not restate
    the volume figures already on the block above it."""
    from core.model import Context, PrimitiveResult

    series = [_tls_series("203.0.113.9", "shop.test", "443", 20)]
    result = PrimitiveResult(
        name="asymmetry", score=0.84, features={"asymmetry": -0.9},
        sample_size=20, method="test",
    )
    evidence = Evidence(
        channel=series[0].channel, series_count=20,
        window=(1_700_000_000.0, 1_700_000_020.0),
        results=(result,), inspections=(),
    )
    flat = _flat(narrate(series, [evidence], source_name="t.pcap"))
    assert "measured asymmetry 0.84" in flat, flat


def test_ranked_rows_print_once_per_channel():
    """A real regression: the row append sat inside the feature loop, so
    each channel printed once per feature with progressively more numbers.
    Three rows sharing one score read as three separate channels."""
    from core.model import PrimitiveResult

    series = [_tls_series("203.0.113.9", "shop.test", "443", 20)]
    result = PrimitiveResult(
        name="asymmetry", score=0.84,
        features={"asymmetry": -0.9, "egress_bytes": 100.0,
                  "ingress_bytes": 900.0},
        sample_size=20, method="test",
    )
    evidence = Evidence(
        channel=series[0].channel, series_count=20,
        window=(1_700_000_000.0, 1_700_000_020.0),
        results=(result,), inspections=(),
    )
    text = narrate(series, [evidence], source_name="t.pcap")

    # The asymmetry ranking names three features, so the bug produced three
    # rows for this one channel.
    # Split on a newline-anchored rule: the section's own header ends in
    # box-drawing characters, so splitting on them bare cuts at the header.
    body = text.split("MOST ONE-SIDED TRANSFER")[1].split("\n──")[0]
    rows = [line for line in body.splitlines() if "203.0.113.9" in line]
    assert len(rows) == 1, rows


# --------------------------------------------------------------------------
# DNS answer section
# --------------------------------------------------------------------------


def _dns_wire(qname: str, answers=(), rcode: int = 0,
              is_response: bool = True) -> bytes:
    """Build a DNS message on the wire, using a compression pointer for every
    answer's owner name — which is what real resolvers emit and what the
    decoder has to handle to see any answer at all.

    `answers` is a sequence of (rtype, ttl, value).
    """
    import socket
    import struct

    def encode(name: str) -> bytes:
        return b"".join(
            bytes([len(label)]) + label.encode("ascii")
            for label in name.split(".")
        ) + b"\x00"

    flags = (0x8000 if is_response else 0) | 0x0100 | (rcode & 0x0F)
    header = struct.pack(">HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    question = encode(qname) + struct.pack(">HH", 1, 1)

    body = b""
    for rtype, ttl, value in answers:
        if rtype == 1:
            rdata = socket.inet_aton(value)
        elif rtype == 28:
            rdata = socket.inet_pton(socket.AF_INET6, value)
        else:
            rdata = encode(value)
        # 0xC00C: pointer to offset 12, the question's name.
        body += (b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, ttl, len(rdata))
                 + rdata)
    return header + question + body


def test_answer_section_is_parsed_through_a_compression_pointer():
    """Every real answer encodes its owner name as a pointer back to the
    question. Refusing pointers — as the question-only decoder did — means
    parsing no answers at all."""
    from capture.decode import dns_message

    wire = _dns_wire("shop.test", [(1, 300, "203.0.113.9")])
    message = dns_message(wire)

    assert message is not None
    assert message.qname == "shop.test", message
    assert len(message.answers) == 1, message.answers
    record = message.answers[0]
    assert (record.name, record.rtype, record.ttl, record.value) == (
        "shop.test", "A", 300, "203.0.113.9"
    ), record


def test_answer_section_reads_aaaa_and_cname():
    from capture.decode import dns_message

    wire = _dns_wire("shop.test", [
        (5, 60, "cdn.example.test"),
        (28, 120, "2001:db8::1"),
    ])
    message = dns_message(wire)
    kinds = {r.rtype: r.value for r in message.answers}
    assert kinds["CNAME"] == "cdn.example.test", kinds
    assert kinds["AAAA"] == "2001:db8::1", kinds


def test_forward_pointer_is_refused_rather_than_followed():
    """A pointer chain can be crafted to loop, and a decoder that follows one
    hangs on a packet an attacker chose. Only strictly-backward jumps are
    legal, which makes a cycle impossible."""
    import struct
    from capture.decode import dns_message

    flags = 0x8000
    header = struct.pack(">HHHHHH", 1, flags, 1, 1, 0, 0)
    question = b"\x04test\x00" + struct.pack(">HH", 1, 1)
    # A self-pointer at its own offset: the shape a loop needs.
    offset = len(header) + len(question)
    body = struct.pack(">H", 0xC000 | offset)
    message = dns_message(header + question + body)

    # Either no answers or a clean None — the requirement is that it returns.
    assert message is None or message.answers == (), message


def test_truncated_answer_section_keeps_the_rcode():
    """A snaplen-clipped response still carries its rcode. Discarding the
    whole record because the tail is missing loses more than it protects."""
    from capture.decode import dns_message

    wire = _dns_wire("shop.test", [(1, 300, "203.0.113.9")], rcode=0)
    message = dns_message(wire[:-6])

    assert message is not None
    assert message.qname == "shop.test", message
    assert message.rcode == 0
    assert message.truncated, message


def test_nxdomain_with_no_answers_is_not_truncated():
    """The inverse: "answered with nothing" must be distinguishable from
    "answers not visible"."""
    from capture.decode import dns_message

    message = dns_message(_dns_wire("nope.test", [], rcode=3))
    assert message.rcode == 3
    assert message.answers == ()
    assert not message.truncated


def test_endpoint_is_named_from_a_dns_answer_without_any_tls():
    """The payoff. Before the answer section was parsed, an endpoint could
    only be named if it happened to speak TLS with an SNI."""
    channel = Channel(
        domain="dns", dims={"proto": "udp", "qtype": "A", "zone": "shop.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "10.0.0.1"),
    )
    answer = Observation(
        ts=1_700_000_000.0, channel=channel, direction=Direction.INGRESS,
        size=80, kind="dns_response",
        attrs={"qname": "shop.test", "qtype": "A", "rcode_name": "NOERROR",
               "resolved_ips": "203.0.113.9", "resolved_count": "1",
               "ttl_min": "300", "answers": "1", "answer_types": "A"},
        locus=Locus(source="t.pcap", frames=(2,)),
    )
    dns = Series(channel, [answer])
    traffic = _tls_series("203.0.113.9", "", "443", 6)

    assert _names([dns])["203.0.113.9"] == "shop.test"
    flat = _flat(narrate([dns, traffic], [], source_name="t.pcap"))
    assert "resolved as shop.test" in flat, flat


def test_sni_wins_over_a_dns_answer_for_the_same_address():
    """SNI is what the client asserted on the wire to that address; a DNS
    answer is an association inferred across two different exchanges."""
    channel = Channel(
        domain="dns", dims={"proto": "udp", "qtype": "A", "zone": "other.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "10.0.0.1"),
    )
    answer = Observation(
        ts=1_700_000_000.0, channel=channel, direction=Direction.INGRESS,
        size=80, kind="dns_response",
        attrs={"qname": "other.test", "rcode_name": "NOERROR",
               "resolved_ips": "203.0.113.9"},
        locus=Locus(source="t.pcap", frames=(2,)),
    )
    names = _names([Series(channel, [answer]),
                    _tls_series("203.0.113.9", "asserted.test", "443", 9)])
    assert names["203.0.113.9"] == "asserted.test", names


# --------------------------------------------------------------------------
# TCP connection outcomes
# --------------------------------------------------------------------------


def test_connection_outcome_classification():
    """The order of the tests in `_Flow.outcome` is the meaning: a RST before
    any SYN-ACK is a refusal, a RST after one is an abort of a working
    connection. Merging them would report "could not connect" and "finished
    rudely" as one number."""
    from capture.pcap import _Flow

    def flow(**flags):
        f = _Flow("10.0.0.5", 1234, 0, responder="203.0.113.9")
        for key, value in flags.items():
            setattr(f, key, value)
        return f

    assert flow(syn=True, synack=True, fin=True).outcome == "closed"
    assert flow(syn=True, synack=True).outcome == "open"
    assert flow(syn=True, synack=True, rst=True).outcome == "reset"
    assert flow(syn=True, rst=True).outcome == "refused"
    assert flow(syn=True).outcome == "unanswered"
    # No SYN seen at all: the capture started mid-connection. Calling that
    # "unanswered" would invent a failure out of a capture-start artefact.
    assert flow(synack=True, fin=True).outcome == "mid_stream"
    assert flow().outcome == "mid_stream"


def test_failed_connections_are_counted_without_any_payload():
    """A refused connection carries no application data, so anything gated
    behind a payload check is blind to exactly the connections that failed.
    This drives real frames through the parser to prove the gate is not
    there."""
    import struct

    from capture.pcap import PcapSource
    from capture.pcapfile import LINKTYPE_ETHERNET

    def tcp_frame(src, dst, sport, dport, flags):
        tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                          1024, 0, 0)
        total = 20 + len(tcp)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                         bytes(int(o) for o in src.split(".")),
                         bytes(int(o) for o in dst.split(".")))
        return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + tcp

    SYN, SYNACK, RST = 0x02, 0x12, 0x04
    frames = [
        # refused: SYN then RST, never answered
        tcp_frame("10.0.0.5", "203.0.113.1", 1111, 443, SYN),
        tcp_frame("203.0.113.1", "10.0.0.5", 443, 1111, RST),
        # unanswered: SYN alone
        tcp_frame("10.0.0.5", "203.0.113.2", 2222, 443, SYN),
        # established
        tcp_frame("10.0.0.5", "203.0.113.3", 3333, 443, SYN),
        tcp_frame("203.0.113.3", "10.0.0.5", 443, 3333, SYNACK),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "conn.pcap"
        with open(path, "wb") as handle:
            handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                     65535, LINKTYPE_ETHERNET))
            for index, frame in enumerate(frames):
                handle.write(struct.pack("<IIII", 1_700_000_000 + index, 0,
                                         len(frame), len(frame)))
                handle.write(frame)

        source = PcapSource(path)
        list(source.observations())  # no payload in any of these frames
        outcomes = source.stats["connections"]

    assert outcomes["counts"].get("refused") == 1, outcomes
    assert outcomes["counts"].get("unanswered") == 1, outcomes
    assert outcomes["counts"].get("open") == 1, outcomes
    assert outcomes["failed"]["refused"] == {"203.0.113.1": 1}, outcomes
    assert outcomes["failed"]["unanswered"] == {"203.0.113.2": 1}, outcomes


def test_connections_section_names_the_unreachable_destinations():
    """"Is this network healthy" is a count; "what could this host not reach"
    is a list. The second is the one an operator acts on."""
    stats = {
        "connections": {
            "counts": {"closed": 90, "refused": 7, "unanswered": 3},
            "failed": {
                "refused": {"203.0.113.1": 5, "203.0.113.2": 2},
                "unanswered": {"203.0.113.3": 3},
            },
            "flows": 100,
        }
    }
    names = {"203.0.113.1": "ns1.example.test"}
    lines = _connections(stats, names, 12)
    text = _flat("\n".join(lines))

    assert "100 TCP flow(s)" in text, text
    assert "7 (  7.0%) refused" in text or "7 ( 7.0%) refused" in text, text
    assert "ns1.example.test" in text, text
    assert "203.0.113.3" in text, text


def test_connections_section_is_omitted_without_tcp():
    """A HAR or a MAVLink capture has no TCP flows, and a section claiming
    zero connections would be a statement about data that does not exist."""
    assert _connections({}, {}, 12) == []
    assert _connections({"connections": {"counts": {}}}, {}, 12) == []


def test_established_reset_is_not_reported_as_a_failure():
    """36.7% of a real capture's connections ended in RST after a working
    handshake. Counting those as failures would have reported a healthy
    network as two-thirds broken."""
    stats = {
        "connections": {
            "counts": {"closed": 60, "reset": 40},
            "failed": {},
            "flows": 100,
        }
    }
    series = [_tls_series("203.0.113.9", "shop.test", "443", 6)]
    flat = _flat(narrate(series, [], stats=stats, source_name="t.pcap"))

    assert "All 100 TCP connections that opened" in flat, flat
    assert "reachability is not" in flat, flat


# --------------------------------------------------------------------------
# exchange trace and activity shape
# --------------------------------------------------------------------------


def _traffic(pattern, interval=1.0, encrypted=True) -> Series:
    """A channel from a list of (direction, size) pairs."""
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443", "sni": "s.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "203.0.113.9"),
    )
    observations = []
    for index, (direction, size) in enumerate(pattern):
        observations.append(Observation(
            ts=1_700_000_000.0 + index * interval,
            channel=channel,
            direction=(Direction.EGRESS if direction == "out"
                       else Direction.INGRESS),
            size=size, kind="tcp_burst",
            attrs={"encrypted": encrypted, "sni": "s.test"},
            locus=Locus(source="t.pcap", frames=(index + 1,)),
        ))
    return Series(channel, observations)


def test_shape_separates_bulk_from_fetch_from_interactive():
    """The hardest claim the tool makes: these three are all encrypted and
    unreadable, and their shapes are still different."""
    from out.narrate import _shape

    bulk = _traffic([("out", 300)] + [("in", 60000)] * 20)
    fetch = _traffic([("out", 400), ("in", 9000)] * 12)
    interactive = _traffic([("out", 60), ("in", 90)] * 15, interval=0.4)

    assert "bulk transfer" in _shape(bulk)[0], _shape(bulk)[0]
    assert "request/response" in _shape(fetch)[0], _shape(fetch)[0]
    assert "interactive" in _shape(interactive)[0] or "regular small" in \
        _shape(interactive)[0], _shape(interactive)[0]


def test_handshake_does_not_misclassify_a_download():
    """REGRESSION. A pure download whose first four exchanges are a TLS
    handshake measures ~45% alternation, and testing alternation before
    volume share reported it as "mixed" while its inbound sizes doubled on
    every step."""
    from out.narrate import _shape

    download = _traffic([
        ("out", 3398), ("in", 3247), ("out", 85), ("in", 43), ("out", 255),
        ("in", 38996), ("in", 58432), ("in", 138112), ("in", 274896),
        ("in", 551120), ("in", 309178), ("in", 23),
    ], interval=0.44)
    verdict, facts = _shape(download)

    assert "bulk transfer" in verdict, verdict
    assert "mixed" not in verdict, verdict
    assert any("100% inbound" in f for f in facts), facts


def test_shape_names_the_benign_reading_too():
    """A shape is not an identity. Several activities share any given shape,
    and a padded implementation can choose its shape."""
    from out.narrate import _shape

    beacon = _traffic([("out", 200), ("in", 180)] * 20, interval=60.0)
    verdict, _facts = _shape(beacon)
    # Whatever it says, it must not assert malice.
    assert "malicious" not in verdict.lower()
    assert "beacon" not in verdict.lower() or "Also" in verdict or \
        "which is why" in verdict, verdict


def test_shape_declines_on_an_empty_channel():
    from out.narrate import _shape
    assert _shape(_traffic([]))[0] == ""


def test_trace_prints_direction_size_and_gap_per_exchange():
    """Aggregation hides the thing someone most wants when asking what a
    conversation is DOING. 5 MB in 1,300 exchanges could be one download or
    1,300 fetches, and the totals are identical."""
    series = _traffic([("out", 300), ("in", 60000), ("in", 60000)],
                      interval=0.5)
    text = "\n".join(narrate([series], [], source_name="t.pcap", trace=1)
                     .splitlines())

    assert "EXCHANGE TRACE" in text, text
    assert "→" in text and "←" in text, text
    assert "300B" in text, text
    # The inter-arrival gap column is what makes a burst visible as a burst.
    assert "0.500s" in text, text


def test_trace_says_when_sizes_and_timing_are_all_there_is():
    series = _traffic([("out", 300), ("in", 60000)], encrypted=True)
    text = narrate([series], [], source_name="t.pcap", trace=1)
    assert "encrypted, so sizes and timing are all that is readable" in text


def test_trace_is_off_unless_asked_for():
    """It is the longest output in the report."""
    series = _traffic([("out", 300), ("in", 60000)])
    assert "EXCHANGE TRACE" not in narrate([series], [], source_name="t.pcap")


def test_trace_truncation_is_announced():
    series = _traffic([("out", 100), ("in", 200)] * 40)
    text = narrate([series], [], source_name="t.pcap", trace=1)
    assert "further exchange(s)" in text, text


def test_record_counts_are_not_printed_per_exchange():
    """REGRESSION. They are flow-level running totals, and printing one
    beside a single exchange reads as "this burst carried 2 records" when
    the burst carried 138 kB and the 2 is cumulative."""
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443", "sni": "s.test"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "203.0.113.9"),
    )
    observations = [
        Observation(
            ts=1_700_000_000.0 + i, channel=channel,
            direction=Direction.INGRESS, size=138112, kind="tcp_burst",
            attrs={"encrypted": True, "tls_rec_in": "2",
                   "tls_rec_in_max": "16400", "tls_rec_in_mean": "9000",
                   "tls_rec_in_full": "1", "tls_rec_in_small": "0"},
            locus=Locus(source="t.pcap", frames=(i + 1,)),
        )
        for i in range(3)
    ]
    series = Series(channel, observations)
    text = narrate([series], [], source_name="t.pcap", trace=1)

    rows = [line for line in text.splitlines() if "138,112B" in line]
    assert rows, text
    for row in rows:
        assert "rec" not in row, row
    # Reported once, in the header, where the number means what it says.
    assert "TLS records:" in text, text
    assert "recv 2 records" in text, text


def test_symmetric_bulk_is_recognised_as_a_tunnel():
    """Found by running against a capture the classifier had never seen:
    84 MB each way, 99% alternation, every size an exact multiple of 1414
    bytes. The rules had no branch for it and said "mixed" — the least
    useful thing available about the most structured channel in the file."""
    from out.narrate import _mtu_quantised, _shape

    tunnel = _traffic(
        [("out", 2828), ("in", 2828), ("out", 1414), ("in", 2828),
         ("out", 2828), ("in", 5656), ("out", 1414), ("in", 1414),
         ("out", 2828), ("in", 4242), ("out", 5656), ("in", 2828)] * 3,
        interval=0.003,
    )
    verdict, facts = _shape(tunnel)

    assert "tunnel" in verdict, verdict
    assert "mixed" not in verdict, verdict
    # The MTU-quantisation note is what distinguishes carried traffic from
    # traffic that merely happens to be symmetric.
    assert "multiples of a fixed unit" in verdict, verdict

    sizes = [1414, 2828, 4242, 5656, 1414, 2828, 2828, 1414, 5656, 2828]
    assert _mtu_quantised(sizes), sizes
    # Ordinary application sizes do not quantise this cleanly.
    assert not _mtu_quantised([1301, 517, 8842, 263, 4001, 917, 20514,
                               333, 7777, 1234])


# --------------------------------------------------------------------------
# per-host view
# --------------------------------------------------------------------------


def _http_channel_to(responder: str, host: str, client: str,
                     count: int = 1) -> Series:
    """An HTTP channel where `responder` is SENT requests for `host`."""
    channel = Channel(
        domain="http", dims={"scheme": "http", "host": host},
        initiator=Entity("ip", client),
        responder=Entity("ip", responder),
    )
    observations = [
        Observation(
            ts=1_700_000_000.0 + i, channel=channel,
            direction=Direction.EGRESS, size=200, kind="http_request",
            attrs={"host": host, "method": "GET", "path": "/",
                   "encrypted": False},
            locus=Locus(source="t.pcap", frames=(i + 1,)),
        )
        for i in range(count)
    ]
    return Series(channel, observations)


def test_http_host_header_does_not_name_the_server():
    """REGRESSION, found on real botnet traffic.

    `Host:` is a claim by the client about where it WANTED to go. Through a
    proxy it names a third party. One request — `GET / Host: www.yahoo.com`
    sent to an infected machine acting as an open proxy — labelled the
    busiest host in a 440,000-frame capture "www.yahoo.com", and every
    section that prints a name repeated it.
    """
    proxied = _http_channel_to("10.0.0.9", "www.yahoo.com", "198.51.100.4")
    names = _names([proxied])

    assert names.get("10.0.0.9") != "www.yahoo.com", names
    assert "10.0.0.9" not in names, names


def test_sni_still_names_the_server():
    """The inverse guard: SNI is addressed to the server that completed the
    handshake, so it remains a usable label."""
    names = _names([_tls_series("203.0.113.9", "shop.test", "443", 5)])
    assert names["203.0.113.9"] == "shop.test", names


def test_host_detail_reports_what_each_originating_host_did():
    """The gap this fills: every other dossier is keyed on the address that
    was REACHED, so "what did this host do" had no section. Invisible on a
    one-host capture; the first question asked on an eight-host one."""
    busy = _dns_series("a.test", [f"h{i}.a.test" for i in range(10)],
                       ["NOERROR"] * 10, client="10.0.0.5")
    quiet = _dns_series("b.test", ["x.b.test"] * 3, ["NXDOMAIN"] * 3,
                        client="10.0.0.6")
    flat = _flat(narrate([busy, quiet], [], source_name="t.pcap"))

    assert "HOST DETAIL" in flat, flat
    assert "2 originating host(s)" in flat, flat
    assert "10.0.0.5" in flat and "10.0.0.6" in flat, flat
    # Per-host DNS outcome, not the capture-wide one.
    assert "lookups resolved" in flat, flat


def test_host_detail_is_ordered_by_volume():
    small = _tls_series("203.0.113.1", "a.test", "443", 2, client="10.0.0.6")
    large = _tls_series("203.0.113.2", "b.test", "443", 40, client="10.0.0.5")
    text = narrate([small, large], [], source_name="t.pcap")

    block = text.split("HOST DETAIL")[1]
    assert block.index("10.0.0.5") < block.index("10.0.0.6"), block[:400]


def test_requests_addressed_elsewhere_are_described_not_judged():
    """A host asked to fetch names that are not its own is acting as a
    proxy. Described, because a reverse proxy and an open one look
    identical from the outside."""
    proxied = _http_channel_to("10.0.0.9", "www.example.test",
                               "198.51.100.4", count=3)
    # Give the receiving host some traffic of its own so it appears.
    own = _tls_series("203.0.113.5", "mine.test", "443", 6,
                      client="10.0.0.9")
    flat = _flat(narrate([proxied, own], [], source_name="t.pcap"))

    assert "addressed to 1 other name" in flat, flat
    assert "www.example.test" in flat, flat
    assert "acting as a proxy" in flat, flat
    # Named both ways, never as a verdict.
    assert "reverse proxy" in flat and "open proxy" in flat, flat
    assert "malicious" not in flat.lower()


def test_host_header_naming_the_server_itself_is_not_proxying():
    """REGRESSION from the first live capture on loopback.

    `Host: 127.0.0.1:18080` delivered to 127.0.0.1 is a client addressing
    the machine it connected to. Fourteen such requests were reported as
    "addressed to other names" because the comparison was against the
    address's resolved NAME, and a bare IP:port never matches one.
    """
    from out.narrate import _addresses_itself

    assert _addresses_itself("127.0.0.1:18080", "127.0.0.1")
    assert _addresses_itself("127.0.0.1", "127.0.0.1")
    assert _addresses_itself("[::1]:8080", "::1")
    assert _addresses_itself("shop.test", "203.0.113.9", known="shop.test")
    # A genuinely different name is still different.
    assert not _addresses_itself("www.yahoo.com", "127.0.0.1")
    assert not _addresses_itself("evil.test:80", "203.0.113.9",
                                 known="shop.test")

    # End to end: a loopback fetch must not be described as proxying.
    local = _http_channel_to("127.0.0.1", "127.0.0.1:18080", "127.0.0.1",
                             count=6)
    flat = _flat(narrate([local], [], source_name="live:lo"))
    assert "acting as a proxy" not in flat, flat


def test_all_private_peers_is_not_reported_as_all_named():
    """On loopback every peer is excluded from the naming question for
    being private. Saying "all could be named" there states the opposite of
    what happened."""
    local = _tls_series("127.0.0.1", "", "8443", 6, client="127.0.0.1")
    flat = _flat(narrate([local], [], source_name="live:lo"))

    assert "private or loopback" in flat, flat
    assert "could be named" not in flat, flat
    assert "loopback (this machine)" in flat, flat


# --------------------------------------------------------------------------


def _ctx():
    from core.model import Context
    return Context(now=1_700_001_000.0, mode="passive")


def _ontologies():
    from ontology import ONTOLOGIES
    return ONTOLOGIES


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
