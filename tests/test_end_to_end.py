"""End-to-end: pcap bytes in, findings out.

Pins the project's central claim as a regression test rather than leaving it
as a one-off terminal run:

    the same capture yields 47 findings against a cold baseline and 2 against
    a warm one, and the two that survive are the two real behaviours.

If a future change breaks the rarity gate, this test fails loudly instead of
the tool quietly reverting to an alert feed full of update checkers.

Synthetic traffic, so these are pipeline assertions and not a detection rate.
"""

from __future__ import annotations

import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.pcap import PcapSource
from core.baseline import NullBaseline, SqliteBaseline
from core.model import Context
from core.score import run
from ontology import ONTOLOGIES
from tools.make_test_pcap import profile_clean, profile_suspect, write_pcap

SEED = 1337


def _analyse(pcap: Path, baseline):
    source = PcapSource(pcap)
    series = list(group_into_series(source.observations(), min_observations=2))
    assert series, "no series produced from capture"
    end = max(s.end or 0.0 for s in series)
    ctx = Context(now=end, baseline=baseline)
    findings, evidences = run(series, ONTOLOGIES, ctx)
    return findings, evidences, source.stats


def _fixtures(tmp: Path):
    clean, suspect = tmp / "clean.pcap", tmp / "suspect.pcap"
    write_pcap(clean, profile_clean(random.Random(SEED)))
    write_pcap(suspect, profile_suspect(random.Random(SEED)))
    return clean, suspect


# --------------------------------------------------------------------------


def test_pcap_reader_decodes_every_frame():
    """A frame the reader silently drops is evidence that vanishes."""
    with tempfile.TemporaryDirectory() as d:
        _, suspect = _fixtures(Path(d))
        _, _, stats = _analyse(suspect, NullBaseline())
        assert stats["frames"] == stats["decoded"] == 560
        assert stats["tcp"] == 420 and stats["dns"] == 140


def test_cold_baseline_over_reports():
    """With no history, the exact pollers all fire. This is the designed
    behaviour, and `warm_up_notice` is what makes it legible to an operator
    rather than looking like a broken tool."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        clean, _ = _fixtures(tmp)
        store = SqliteBaseline(tmp / "cold.db")
        assert store.warm_up_notice(now=0.0) is not None

        findings, _, _ = _analyse(clean, store)
        pollers = [f for f in findings if f.channel.dims.get("dport") == "443"]
        assert len(findings) > 30, f"expected over-reporting, got {len(findings)}"
        assert pollers, "expected the exact-interval pollers to fire"


def test_warm_baseline_suppresses_the_prevalent_poller():
    """THE CENTRAL CLAIM.

    A 300s exact-interval poller scores 1.000 on periodicity — identical to a
    zero-jitter beacon. Prevalence is the only thing that separates them, and
    it must be the thing that suppresses this one.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        clean, suspect = _fixtures(tmp)
        store = SqliteBaseline(tmp / "warm.db")

        cold_findings, _, _ = _analyse(clean, store)   # also warms the store
        warm_findings, evidences, _ = _analyse(suspect, store)

        assert len(warm_findings) < len(cold_findings) / 5, (
            f"rarity gate not working: {len(cold_findings)} cold vs "
            f"{len(warm_findings)} warm"
        )

        fired = {f.channel.responder.value for f in warm_findings}
        assert "203.0.113.9" in fired, "jittered beacon did not fire"
        assert "10.0.0.53" in fired, "dns tunnel did not fire"
        assert "10.0.0.1" not in fired, "prevalent poller was not suppressed"
        assert "93.184.216.34" not in fired, "ordinary browsing fired"

        # Suppression must come from prevalence, not from a thin-baseline or
        # clock artefact that happens to drive recency to zero.
        poller = next(
            e for e in evidences
            if e.channel.responder and e.channel.responder.value == "10.0.0.1"
        )
        assert poller.score_of("periodicity") > 0.95, "poller should look perfectly periodic"
        assert poller.feature("rarity", "prevalence", 0.0) > 0.9, "poller should be prevalent"
        assert poller.score_of("rarity") < 0.5, "rarity should gate it out"
        assert poller.feature("rarity", "recency", 0.0) > 0.5, (
            "suppression must be by prevalence, not by a recency/clock artefact"
        )


def test_beacon_measurements_are_accurate():
    """The reported period must match the traffic that was generated.

    The synthetic beacon is uniform in [48s, 60s], so the median interval
    should land near 54s. A burst-gap misconfiguration would fragment the
    exchanges and report a far shorter period — the most likely way to get
    this silently wrong.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        clean, suspect = _fixtures(tmp)
        store = SqliteBaseline(tmp / "warm.db")
        _analyse(clean, store)
        findings, _, _ = _analyse(suspect, store)

        beacon = next(f for f in findings if f.channel.responder.value == "203.0.113.9")
        period = beacon.evidence.feature("periodicity", "period_s")
        assert 50.0 < period < 58.0, f"period {period} outside the generated band"
        assert beacon.evidence.feature("periodicity", "observations") == 40
        assert beacon.display_filter == "tcp.stream eq 16"
        assert beacon.confidence > 0.7


def test_no_baseline_disables_rarity_gated_rules():
    """NullBaseline must silence rules rather than score everything as rare."""
    with tempfile.TemporaryDirectory() as d:
        _, suspect = _fixtures(Path(d))
        findings, evidences, _ = _analyse(suspect, NullBaseline())
        assert all(e.by_name("rarity") is None for e in evidences), (
            "rarity produced a score with no history"
        )
        assert not any(f.rule_id.startswith("net.beacon") for f in findings), (
            "a rarity-gated rule fired without a baseline"
        )


def test_display_filters_stay_pasteable():
    """A filter thousands of characters long cannot be used."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        clean, suspect = _fixtures(tmp)
        store = SqliteBaseline(tmp / "warm.db")
        _analyse(clean, store)
        findings, _, _ = _analyse(suspect, store)

        for finding in findings:
            assert finding.display_filter
            assert len(finding.display_filter) < 400, (
                f"{finding.rule_id} filter is {len(finding.display_filter)} chars"
            )


def test_soc_event_carries_flow_timing():
    """The SOC integration exists to replace poll-derived timing with
    flow-derived timing. If `period_s` is absent, it is pointless."""
    from out.sinks import soc_event

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        clean, suspect = _fixtures(tmp)
        store = SqliteBaseline(tmp / "warm.db")
        _analyse(clean, store)
        findings, _, _ = _analyse(suspect, store)

        beacon = next(f for f in findings if f.channel.responder.value == "203.0.113.9")
        event = soc_event(beacon, host="sensor-1")
        assert event["tags"] and "beacon_pattern" in event["tags"]
        assert 50.0 < event["details"]["period_s"] < 58.0
        assert event["details"]["interval_mad_s"] > 0
        assert event["details"]["remote_ip"] == "203.0.113.9"
        assert event["evidence"]["primitives"], "arithmetic trail missing"


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
