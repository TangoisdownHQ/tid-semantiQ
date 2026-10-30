"""Modbus/TCP — the domain-onboarding test.

The project has claimed since the spec that adding a domain is a parser plus
a `dims` choice, with no new mathematics. This suite is the test of that
claim, and `test_domain_reuses_the_existing_primitives` asserts it directly.

The claim mostly held: no new primitive, no contract change, two small
classifier inspectors. What it did NOT survive was calibration. Three
defaults tuned for web traffic were wrong here, each in a way that produced
silence or nonsense rather than an error:

  test_periodicity_must_be_grouped_by_function_code
      a steady 1s scan cycle scored 0.001 and a flat-rate scanner scored
      1.000 — exactly backwards
  test_fanout_counts_requests_not_responses
      responses echo the unit id, halving the apparent concentration of a
      sweep
  test_novelty_not_blended_rarity_identifies_a_new_source
      rarity scored 0.40 for the established master and 0.40 for the rogue
"""

from __future__ import annotations

import random
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from core.baseline import SqliteBaseline
from core.model import Context
from core.primitives import stack_for
from core.score import analyse_series, run
from inspectors import inspectors_for
from ontology import ONTOLOGIES
from tools.make_modbus_pcap import MASTER, PLC, PROFILES, ROGUE, write_pcap

HAVE_TSHARK = shutil.which("tshark") is not None

MODBUS_PRIMITIVES = {
    "periodicity", "jitter", "burstiness", "rarity",
    "fanout.unit", "fanout.fc", "web.timing_differential",
}


def _pcap(tmp: Path, profile: str) -> Path:
    path = tmp / f"modbus-{profile}.pcap"
    write_pcap(path, PROFILES[profile](random.Random(20261024)))
    return path


def _series(path: Path):
    from capture.tshark import ModbusProfile, TsharkSource

    source = TsharkSource(path, profile=ModbusProfile())
    series = list(group_into_series(source.observations(), min_observations=1))
    return series, source


def _analyse(tmp: Path, profile: str, baseline: SqliteBaseline):
    series, _ = _series(_pcap(tmp, profile))
    ctx = Context(now=max(s.end or 0.0 for s in series), baseline=baseline)
    return run(series, ONTOLOGIES, ctx)


def _trained(tmp: Path) -> SqliteBaseline:
    """A baseline that has seen normal operations once."""
    baseline = SqliteBaseline(tmp / "ics.db")
    _analyse(tmp, "normal", baseline)
    return baseline


def _channel(series, host):
    return next(s for s in series if s.channel.initiator.value == host)


def _rules(findings):
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------
# the architectural claim
# --------------------------------------------------------------------------


def test_domain_reuses_the_existing_primitives():
    """No new mathematics. Every Modbus primitive already existed for other
    domains; only the attribute names differ."""
    assert {p.name for p in stack_for("modbus")} == MODBUS_PRIMITIVES
    # And the two inspectors are classifiers, not judges — the protocol has
    # no authentication, so no single message is anomalous by itself.
    assert {i.name for i in inspectors_for("modbus")} == {
        "ics.modbus_command", "ics.modbus_exception",
    }


def test_latency_analyzer_works_unchanged_on_modbus():
    """`ResponseTimeDifferential` was written for HTTP and takes its
    attribute names as parameters. Wireshark supplies
    `modbus.response_time`, so it transfers with no code change — which is
    what parameterising it bought."""
    assert "web.timing_differential" in {p.name for p in stack_for("modbus")}
    primitive = next(
        p for p in stack_for("modbus") if p.name == "web.timing_differential"
    )
    assert primitive.group_attr == "fc"
    assert primitive.elapsed_attr == "elapsed_s"


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


def test_requests_and_responses_pair_completely():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, source = _series(_pcap(Path(d), "normal"))
        assert len(series) == 1
        one = series[0]
        assert one.channel.initiator.value == MASTER
        assert one.channel.responder.value == PLC

        txns = one.group_by("txn")
        assert len(txns) == 120
        for txn, group in txns.items():
            kinds = sorted(o.kind for o in group)
            assert kinds == ["modbus_request", "modbus_response"], (txn, kinds)


def test_exception_responses_are_not_mistaken_for_requests():
    """A REAL BUG this caught.

    Wireshark does not populate `modbus.request_frame` on exception
    responses, so a "response is the one with a request pointer" test
    classified all 36 exceptions as requests — swapping master and PLC and
    inventing a third channel in which the PLC appeared to be issuing
    commands to the scanner.
    """
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "scan"))

        # The PLC must never appear as an initiator.
        initiators = {s.channel.initiator.value for s in series}
        assert PLC not in initiators, (
            f"the PLC was classified as a master: {initiators}"
        )
        assert initiators == {MASTER, ROGUE}

        exceptions = [
            o for s in series for o in s
            if "exception" in o.attrs
        ]
        assert exceptions, "no exceptions parsed"
        assert all(o.kind == "modbus_response" for o in exceptions)


def test_transaction_id_pairs_exceptions_too():
    """Pairing uses Modbus's own `mbtcp.trans_id`, which both sides carry,
    rather than Wireshark's frame cross-reference — which is absent on
    exceptions and would leave every one of them unpaired."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "scan"))
        scanner = _channel(series, ROGUE)
        for txn, group in scanner.group_by("txn").items():
            assert len(group) == 2, (txn, [o.kind for o in group])


def test_function_codes_are_categorised():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "write"))
        rogue = _channel(series, ROGUE)
        categories = {
            o.attrs["category"] for o in rogue.filter(kind="modbus_request")
        }
        assert categories == {"write"}

        master = _channel(series, MASTER)
        assert {
            o.attrs["category"] for o in master.filter(kind="modbus_request")
        } == {"read"}


# --------------------------------------------------------------------------
# the three calibration defects
# --------------------------------------------------------------------------


def test_periodicity_must_be_grouped_by_function_code():
    """A master polling two function codes 50ms apart on a 1s cycle yields
    intervals of 0.05, 0.95, 0.05, 0.95. Measured whole that is bimodal and
    scores ~0; grouped by function code it is the clean 1s cadence it
    actually is.

    Measured before the fix: steady master 0.001, flat-rate scanner 1.000.
    """
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from core.primitives.timing import Periodicity
    from core.model import Direction

    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "normal"))
        one = series[0]
        ctx = Context(now=one.end or 0.0)

        ungrouped = Periodicity(direction=Direction.EGRESS).run(one, ctx)
        grouped = Periodicity(
            direction=Direction.EGRESS, group_attr="fc"
        ).run(one, ctx)

        assert grouped is not None
        assert grouped.score > 0.9, grouped.features
        assert 0.95 < grouped.features["period_s"] < 1.05, (
            "the 1s scan cycle was not recovered"
        )
        assert grouped.features["groups_measured"] == 2
        # And the ungrouped measurement is the one that was wrong.
        assert ungrouped is None or ungrouped.score < 0.2, (
            "the ungrouped series should look aperiodic; if it does not, this "
            "test has stopped demonstrating why grouping is needed"
        )


def test_fanout_counts_requests_not_responses():
    """Responses echo the unit id, so counting both halved the apparent
    concentration of a sweep: 24 unique over 80 messages rather than over
    40 requests."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    from core.primitives.structure import Fanout

    with tempfile.TemporaryDirectory() as d:
        series, _ = _series(_pcap(Path(d), "scan"))
        scanner = _channel(series, ROGUE)
        ctx = Context(now=scanner.end or 0.0)

        both = Fanout(attr="unit", saturation=12).run(scanner, ctx)
        requests_only = Fanout(
            attr="unit", kind="modbus_request", saturation=12
        ).run(scanner, ctx)

        assert both is not None and requests_only is not None
        assert requests_only.features["unique_values"] == 24
        assert requests_only.score > both.score, (
            "filtering to requests should concentrate the signal"
        )
        assert requests_only.score >= 0.5


def test_novelty_not_blended_rarity_identifies_a_new_source():
    """Rarity's blended score cannot answer "is this source new".

    `prevalence` drops the initiator by design, so on a one-master network
    "something talks to this PLC" is 100% prevalent and a second master is
    invisible. `recency` spans days, so both channels read as recent inside
    one capture. Measured: 0.40 for the established master and 0.40 for the
    rogue — no discrimination at all. `novel` separates them.
    """
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)

        series, _ = _series(_pcap(tmp, "write"))
        ctx = Context(now=max(s.end or 0.0 for s in series), baseline=baseline)

        established = analyse_series(_channel(series, MASTER), ctx)
        rogue = analyse_series(_channel(series, ROGUE), ctx)

        # The blended score does not separate them...
        assert abs(
            established.score_of("rarity") - rogue.score_of("rarity")
        ) < 0.05, "if rarity now discriminates, this test is obsolete"

        # ...but novelty does.
        assert established.feature("rarity", "novel") == 0.0
        assert rogue.feature("rarity", "novel") == 1.0
        assert established.feature("rarity", "historical_observations") > 100


def test_empty_grammar_sequence_order_declines():
    """`SequenceOrder(allowed=frozenset())` permits nothing, so it scored
    every transition as a violation — 1.0 on perfectly valid traffic. It
    shipped in the modbus stack as a placeholder and was inert only because
    no rule referenced it."""
    from core.primitives.structure import SequenceOrder
    from core.model import Channel, Direction, Entity, Observation, Series

    channel = Channel(domain="modbus", dims={"proto": "modbus"},
                      initiator=Entity("ip", MASTER),
                      responder=Entity("ip", PLC))
    obs = [
        Observation(ts=float(i), channel=channel, direction=Direction.EGRESS,
                    size=12, attrs={},
                    kind="modbus_request" if i % 2 == 0 else "modbus_response")
        for i in range(10)
    ]
    series = Series(channel, obs)
    ctx = Context(now=10.0)

    assert SequenceOrder(allowed=frozenset()).run(series, ctx) is None
    # With a real grammar it works normally.
    grammar = frozenset({
        ("modbus_request", "modbus_response"),
        ("modbus_response", "modbus_request"),
    })
    result = SequenceOrder(allowed=grammar, grammar_id="modbus.v1").run(series, ctx)
    assert result is not None and result.score == 0.0
    assert "modbus" not in {p.name for p in stack_for("modbus")}


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


def test_normal_operations_are_silent():
    """Reads on a steady cycle from the established master must produce
    nothing, twice over. A control-network tool that alerts on normal
    polling is switched off on day one."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "normal", baseline)
        assert not findings, [f.rule_id for f in findings]


def test_rogue_write_is_critical():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "write", baseline)

        unauthorized = next(
            (f for f in findings
             if f.rule_id == "modbus.command.unauthorized_write"), None
        )
        assert unauthorized is not None, _rules(findings)
        assert unauthorized.severity.value == "critical"
        assert unauthorized.channel.initiator.value == ROGUE

        # Category-scoped evidence name: folding keeps the worst result per
        # name, so emitting writes and diagnostics under one name discarded
        # the lower-scoring category and broke any rule gating on it.
        facts = unauthorized.evidence.by_name("ics.modbus_command.write").facts
        assert facts["category"] == "write"
        assert "ics-attack:T0855" in unauthorized.refs
        # The specific rule supersedes the general "write observed" one.
        assert "modbus.command.write_observed" not in _rules(findings)


def test_write_from_the_established_master_is_not_critical():
    """The gate must work in both directions. A write from the host that has
    always written is operations, not an attack."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        # Train on the write profile itself, so the rogue is no longer novel.
        baseline = SqliteBaseline(tmp / "ics.db")
        _analyse(tmp, "write", baseline)
        findings, _ = _analyse(tmp, "write", baseline)

        assert "modbus.command.unauthorized_write" not in _rules(findings)
        assert "modbus.command.write_observed" in _rules(findings)


def test_scanner_is_detected_as_enumeration():
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "scan", baseline)
        rules = _rules(findings)

        assert "modbus.recon.unit_enumeration" in rules
        assert "modbus.recon.function_enumeration" in rules

        units = next(
            f for f in findings if f.rule_id == "modbus.recon.unit_enumeration"
        )
        assert units.channel.initiator.value == ROGUE
        assert units.evidence.feature("fanout.unit", "unique_values") == 24
        # The exception volume corroborates, via a Boost with a stated reason.
        trail = " ".join(units.evidence.by_name("_scoring").notes)
        assert "exception" in trail


def test_exception_volume_is_low_on_its_own():
    """A misconfigured master produces exceptions too, so this earns its
    keep as corroboration rather than as an alert."""
    if not HAVE_TSHARK:
        print("      (skipped: tshark not on PATH)")
        return
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        baseline = _trained(tmp)
        findings, _ = _analyse(tmp, "scan", baseline)
        volume = next(
            (f for f in findings
             if f.rule_id == "modbus.error.exception_volume"), None
        )
        assert volume is not None
        assert volume.severity.value == "low"


def test_findings_use_ics_attack_not_enterprise_attack():
    """Mapping a PLC write to an enterprise technique would mislead."""
    for rule in ONTOLOGIES["modbus"].rules:
        assert rule.refs, rule.id
        assert any(r.startswith("ics-attack:") for r in rule.refs), rule.id
        assert not any(
            r.startswith("attack:T1") for r in rule.refs
        ), f"{rule.id} uses an enterprise technique"


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
          + ("" if HAVE_TSHARK else "   (tshark absent: capture tests skipped)"))
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
