"""Sliding windows over a stream.

`test_streaming_matches_batch_when_the_window_fits` is the one that matters:
the same capture analysed whole and analysed through the windower must reach
the same findings, or the streaming path is a different tool wearing the same
name.

`test_undersized_window_is_reported` pins the failure that discovery
exposed. A 54-second beacon needs six callbacks, so about 324 seconds. At
`--window 300` the analysis does not fail — it silently finds nothing, which
reads as a clean link. The arithmetic is simple enough to just do, so the
operator is told.
"""

from __future__ import annotations

import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.pcap import PcapSource
from capture.window import SlidingWindower
from core.baseline import SqliteBaseline
from core.model import (
    Channel,
    Context,
    Direction,
    Entity,
    Locus,
    Observation,
)
from core.score import run
from ontology import ONTOLOGIES
from out.stream import FindingAggregator
from tools.make_test_pcap import profile_clean, profile_suspect, write_pcap

SEED = 1337


def _channel(name: str) -> Channel:
    return Channel(
        domain="net",
        dims={"proto": "tcp", "dport": "443", "sni": name},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "203.0.113.9"),
    )


def _obs(ts: float, channel: Channel) -> Observation:
    return Observation(
        ts=ts,
        channel=channel,
        direction=Direction.EGRESS,
        size=500,
        kind="tcp_burst",
        attrs={"encrypted": True},
        locus=Locus("t.pcap", frames=(int(ts) + 1,), stream=0),
    )


def _stream(channel: Channel, start: float, step: float, count: int):
    return [_obs(start + index * step, channel) for index in range(count)]


# --------------------------------------------------------------------------
# the contract
# --------------------------------------------------------------------------


def test_feed_is_eager():
    """A generator `feed()` only accepted an observation when the caller
    advanced the iterator, so discarding the result dropped it silently."""
    windower = SlidingWindower(window_s=100, emit_every_s=50)
    channel = _channel("a")
    for obs in _stream(channel, 0.0, 1.0, 10):
        windower.feed(obs)                      # result deliberately unused
    assert windower.stats["observations"] == 10
    assert windower.active_channels == 1


def test_emission_uses_event_time_not_wall_clock():
    """Two identical streams must produce identical windows however long the
    feeding takes in real time — otherwise replaying a capture could never
    test streaming behaviour."""
    channel = _channel("a")
    observations = _stream(channel, 1000.0, 10.0, 40)

    first = SlidingWindower(window_s=100, emit_every_s=50)
    second = SlidingWindower(window_s=100, emit_every_s=50)

    a = [len(batch) for batch in first.feed_windows(observations)]
    b = [len(batch) for batch in second.feed_windows(observations)]
    assert a == b
    assert first.stats == second.stats
    # ...and the clock is the stream's, so the watermark is a data timestamp.
    assert first.watermark == observations[-1].ts


def test_windows_slide_rather_than_tumble():
    """Each emission carries the last `window_s`, so an analysis sees more
    evidence each time. Tumbling windows short enough to be responsive would
    never accumulate the six observations `Periodicity` needs."""
    channel = _channel("a")
    windower = SlidingWindower(window_s=100, emit_every_s=25)
    sizes = [
        batch[0].count
        for batch in windower.feed_windows(_stream(channel, 0.0, 5.0, 40))
        if batch
    ]
    assert sizes, "no windows emitted"
    # Growing, then steady once the window is full — never resetting to a
    # handful, which is what tumbling would show.
    assert sizes[0] < max(sizes)
    assert min(sizes[1:]) > 2


def test_long_gap_closes_every_intervening_window():
    """A stream that jumps forward must not skip deadlines silently — an
    analysis waiting on a boundary would never see it."""
    channel = _channel("a")
    windower = SlidingWindower(window_s=1000, emit_every_s=10)
    windower.feed(_obs(0.0, channel))
    windower.feed(_obs(1.0, channel))
    assert windower.stats["windows"] == 0
    windower.feed(_obs(100.0, channel))         # jumps ten deadlines
    assert windower.stats["windows"] == 10


def test_flush_emits_the_final_partial_window():
    """Without it the last window is lost, which on a short capture can be
    most of the evidence."""
    channel = _channel("a")
    windower = SlidingWindower(window_s=1000, emit_every_s=1000)
    for obs in _stream(channel, 0.0, 1.0, 10):
        windower.feed(obs)
    assert windower.stats["windows"] == 0       # no deadline reached
    final = list(windower.flush())
    assert len(final) == 1 and final[0].count == 10


# --------------------------------------------------------------------------
# bounded memory
# --------------------------------------------------------------------------


def test_stale_channels_are_evicted():
    """Memory is bounded by eviction, not by hoping streams end."""
    windower = SlidingWindower(window_s=50, emit_every_s=25)
    old, new = _channel("old"), _channel("new")
    for obs in _stream(old, 0.0, 1.0, 5):
        windower.feed(obs)
    for obs in _stream(new, 200.0, 1.0, 5):
        windower.feed(obs)
    assert windower.stats["evicted_stale"] >= 1
    assert windower.active_channels == 1


def test_channel_cap_sheds_load_and_says_so():
    """A port scan creates channels faster than they age out. Shedding is
    correct; shedding SILENTLY would turn a flood into a quiet network."""
    windower = SlidingWindower(
        window_s=1000, emit_every_s=1000, max_channels=5
    )
    for index in range(50):
        windower.feed(_obs(float(index), _channel(f"host{index}")))
    assert windower.active_channels <= 5
    assert windower.stats["evicted_overflow"] >= 45

    pressure = windower.pressure()
    assert pressure is not None
    assert "channel cap" in pressure
    assert "less traffic than the link carried" in pressure


def test_per_channel_cap_drops_oldest_and_counts_it():
    windower = SlidingWindower(
        window_s=10_000, emit_every_s=10_000, max_per_channel=20
    )
    channel = _channel("a")
    for obs in _stream(channel, 0.0, 1.0, 100):
        windower.feed(obs)
    series = list(windower.flush())
    assert series[0].count == 20
    assert windower.stats["dropped_per_channel"] == 80
    assert "per-channel cap" in (windower.pressure() or "")


def test_late_observations_are_counted_not_hidden():
    """Badly reordered timestamps should be visible as such, not as a thin
    result."""
    windower = SlidingWindower(window_s=10, emit_every_s=10)
    channel = _channel("a")
    windower.feed(_obs(1000.0, channel))
    windower.feed(_obs(1001.0, channel))
    windower.feed(_obs(100.0, channel))         # far behind the watermark
    assert windower.stats["late"] == 1
    assert "late" in (windower.pressure() or "")


def test_clean_stream_reports_no_pressure():
    windower = SlidingWindower(window_s=1000, emit_every_s=100)
    for obs in _stream(_channel("a"), 0.0, 1.0, 50):
        windower.feed(obs)
    assert windower.pressure() is None


# --------------------------------------------------------------------------
# the cadence advisory
# --------------------------------------------------------------------------


def test_undersized_window_is_reported():
    """THE FAILURE DISCOVERY EXPOSED.

    `Periodicity` needs six observations. A channel averaging 54 seconds
    between them needs about 324 seconds of window, and at 300 the analysis
    finds nothing rather than finding something weak. Measured on the
    fixtures before this advisory existed: the beacon was found in batch mode
    and missed at `--window 300`.
    """
    windower = SlidingWindower(window_s=300, emit_every_s=60)
    for obs in _stream(_channel("slow"), 0.0, 54.0, 40):
        windower.feed(obs)

    warning = windower.undersized_window()
    assert warning is not None
    assert "--window 300s is too short" in warning
    assert "are absent" in warning


def test_adequate_window_reports_nothing():
    windower = SlidingWindower(window_s=1200, emit_every_s=300)
    for obs in _stream(_channel("slow"), 0.0, 54.0, 40):
        windower.feed(obs)
    assert windower.undersized_window() is None


def test_cadence_survives_eviction():
    """The advisory compares the window against what the LINK carries, so
    evicting a channel must not erase the cadence it demonstrated."""
    windower = SlidingWindower(window_s=100, emit_every_s=50)
    for obs in _stream(_channel("slow"), 0.0, 54.0, 10):
        windower.feed(obs)
    for obs in _stream(_channel("other"), 5000.0, 1.0, 5):
        windower.feed(obs)
    assert windower.stats["evicted_stale"] >= 1
    assert windower.undersized_window() is not None


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------


def test_aggregator_collapses_repeats_and_keeps_the_best():
    """A sliding window re-finds the same defect every window. The operator
    must see it once, at its best-evidenced confidence."""
    from core.model import Evidence, Finding, Severity

    channel = _channel("a")
    evidence = Evidence(channel=channel, series_count=10, window=(0.0, 10.0),
                        results=(), inspections=())

    def finding(confidence: float) -> Finding:
        return Finding(
            rule_id="net.beacon.periodic_callback", title="t",
            channel=channel, severity=Severity.HIGH,
            confidence=confidence, evidence=evidence,
        )

    aggregator = FindingAggregator()
    for confidence in (0.60, 0.75, 0.70, 0.90, 0.80):
        aggregator.begin_window()
        aggregator.add([finding(confidence)], [evidence])

    collapsed = aggregator.findings()
    assert len(collapsed) == 1
    assert collapsed[0].confidence == 0.90      # best, not first or last

    entry = aggregator.streamed()[0]
    assert entry.windows_seen == 5
    assert entry.persistent and entry.strengthened
    assert entry.lowest_confidence == 0.60


def test_aggregator_flags_a_transient_finding():
    """One window out of many may be a boundary artefact, and the operator is
    the one who can tell."""
    from core.model import Evidence, Finding, Severity

    channel = _channel("a")
    evidence = Evidence(channel=channel, series_count=3, window=(0.0, 3.0),
                        results=(), inspections=())
    aggregator = FindingAggregator()
    for index in range(10):
        aggregator.begin_window()
        if index == 4:
            aggregator.add([Finding(
                rule_id="net.beacon.periodic_callback", title="t",
                channel=channel, severity=Severity.HIGH, confidence=0.7,
                evidence=evidence,
            )], [evidence])
        else:
            aggregator.add([], [evidence])

    entry = aggregator.streamed()[0]
    assert entry.windows_seen == 1
    assert not entry.persistent
    notes = aggregator.notes()
    assert notes and "only one of 10 windows" in notes[0]


# --------------------------------------------------------------------------
# equivalence with batch
# --------------------------------------------------------------------------


def _batch(pcap: Path, baseline):
    series = list(group_into_series(
        PcapSource(pcap).observations(), min_observations=1
    ))
    ctx = Context(now=max(s.end or 0.0 for s in series), baseline=baseline)
    findings, _ = run(series, ONTOLOGIES, ctx, record=False)
    return {f.rule_id for f in findings}


def _streamed(pcap: Path, baseline, window_s: float, emit_s: float):
    windower = SlidingWindower(window_s=window_s, emit_every_s=emit_s)
    aggregator = FindingAggregator()
    for batch in windower.feed_windows(PcapSource(pcap).observations()):
        aggregator.begin_window()
        now = max((s.end or 0.0) for s in batch)
        ctx = Context(now=now, baseline=baseline)
        findings, evidences = run(batch, ONTOLOGIES, ctx, record=False)
        aggregator.add(findings, evidences)
    return {f.rule_id for f in aggregator.findings()}, windower


def test_streaming_matches_batch_when_the_window_fits():
    """THE EQUIVALENCE TEST.

    Analysed whole and analysed through a window wide enough to hold the
    cadences present, the same capture must reach the same findings — or the
    streaming path is a different tool wearing the same name.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        clean, suspect = tmp / "clean.pcap", tmp / "suspect.pcap"
        write_pcap(clean, profile_clean(random.Random(SEED)))
        write_pcap(suspect, profile_suspect(random.Random(SEED)))

        baseline = SqliteBaseline(tmp / "b.db")
        series = list(group_into_series(
            PcapSource(clean).observations(), min_observations=1
        ))
        ctx = Context(now=max(s.end or 0.0 for s in series), baseline=baseline)
        run(series, ONTOLOGIES, ctx)            # warm the baseline

        batch = _batch(suspect, baseline)
        streamed, windower = _streamed(suspect, baseline, 1200.0, 300.0)

        assert batch, "batch mode found nothing; the fixture changed"
        assert streamed == batch, (
            f"only in batch: {batch - streamed}; "
            f"only in stream: {streamed - batch}"
        )
        assert windower.undersized_window() is None


def test_too_short_a_window_loses_findings_and_says_why():
    """The converse, and the reason the advisory exists: a window below the
    cadence does not weaken the finding, it removes it."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        clean, suspect = tmp / "clean.pcap", tmp / "suspect.pcap"
        write_pcap(clean, profile_clean(random.Random(SEED)))
        write_pcap(suspect, profile_suspect(random.Random(SEED)))

        baseline = SqliteBaseline(tmp / "b.db")
        series = list(group_into_series(
            PcapSource(clean).observations(), min_observations=1
        ))
        ctx = Context(now=max(s.end or 0.0 for s in series), baseline=baseline)
        run(series, ONTOLOGIES, ctx)

        batch = _batch(suspect, baseline)
        streamed, windower = _streamed(suspect, baseline, 300.0, 60.0)

        assert streamed < batch, "a 300s window should lose the slow beacon"
        assert "net.beacon.periodic_callback" in batch - streamed
        # ...and the operator is told, rather than left with a clean result.
        assert windower.undersized_window() is not None


def test_streaming_does_not_write_the_baseline():
    """A sliding window re-emits the same observations, so recording each
    emission would multiply a channel's history by the windows it survived
    and make prevalence meaningless."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        suspect = tmp / "suspect.pcap"
        write_pcap(suspect, profile_suspect(random.Random(SEED)))

        baseline = SqliteBaseline(tmp / "b.db")
        before = baseline.describe_denominator()
        _streamed(suspect, baseline, 1200.0, 300.0)
        assert baseline.describe_denominator() == before == "empty baseline"


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
