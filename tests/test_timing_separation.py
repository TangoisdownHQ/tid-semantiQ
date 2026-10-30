"""Does the periodicity primitive actually separate beacons from noise?

This is the test that decides whether the architecture is worth building on.
If MAD-based scoring cannot tell a 50%-jittered callback from ordinary
traffic, no amount of plugin design or multi-domain abstraction saves the
tool.

Synthetic series only — these are unit tests of the statistics, not an
evaluation. The real numbers come from lab ground truth: Sliver or Havoc at
0/20/50/90% jitter, against a week of clean traffic as the false-positive
denominator. Nothing here may be quoted as a detection rate.
"""

from __future__ import annotations

import random

from capture.base import BurstAssembler
from core.model import Channel, Context, Direction, Entity, Observation, Series
from core.primitives.timing import Burstiness, Jitter, Periodicity

SEED = 1337
CTX = Context(now=1_700_000_000.0)

CHANNEL = Channel(
    domain="net",
    dims={"proto": "tcp", "dport": "443"},
    initiator=Entity("ip", "10.0.0.5"),
    responder=Entity("ip", "203.0.113.9"),
)


def _series(intervals, sizes=None, start=1_699_000_000.0):
    """Build an EGRESS series from a list of inter-arrival times."""
    ts = [start]
    for gap in intervals:
        ts.append(ts[-1] + gap)
    sizes = sizes or [512] * len(ts)
    obs = [
        Observation(
            ts=t,
            channel=CHANNEL,
            direction=Direction.EGRESS,
            size=s,
            kind="tcp_burst",
            attrs={"encrypted": True},
        )
        for t, s in zip(ts, sizes)
    ]
    return Series(CHANNEL, obs)


def _jittered(period, jitter_pct, n, rng):
    """Cobalt-Strike-style jitter: interval uniform in [p*(1-j), p]."""
    low = period * (1.0 - jitter_pct)
    return [rng.uniform(low, period) for _ in range(n)]


# --------------------------------------------------------------------------


def test_periodicity_survives_jitter():
    """A jittered beacon must stay clearly above unstructured traffic.

    This is the claim the naive `max - min` test cannot make: any jitter at
    all puts the interval range outside tolerance and the detector goes
    silent.
    """
    rng = random.Random(SEED)
    prim = Periodicity(direction=Direction.EGRESS)

    scores = {}
    for jitter in (0.0, 0.20, 0.50, 0.90):
        series = _series(_jittered(60.0, jitter, 40, rng))
        result = prim.run(series, CTX)
        assert result is not None, f"no result at jitter={jitter}"
        scores[jitter] = result.score

    # Unstructured baseline: memoryless arrivals at the same mean rate.
    noise = _series([rng.expovariate(1 / 60.0) for _ in range(40)])
    noise_result = prim.run(noise, CTX)
    assert noise_result is not None
    noise_score = noise_result.score

    for jitter in (0.0, 0.20, 0.50):
        assert scores[jitter] > noise_score + 0.2, (
            f"jitter={jitter} scored {scores[jitter]:.3f}, "
            f"not separated from noise {noise_score:.3f}"
        )

    # Monotonic degradation, not a cliff.
    assert scores[0.0] >= scores[0.20] >= scores[0.50]


def test_naive_range_test_fails_where_mad_holds():
    """Demonstrate the defect this primitive exists to fix.

    The range test used by connection-polling detectors is
    `max(intervals) - min(intervals) <= max(2.0, mean * 0.2)`. At 50% jitter
    it does not fire; MAD scoring still does.
    """
    rng = random.Random(SEED)
    intervals = _jittered(60.0, 0.50, 40, rng)

    naive_variance = max(intervals) - min(intervals)
    naive_mean = sum(intervals) / len(intervals)
    naive_fires = naive_variance <= max(2.0, naive_mean * 0.2)
    assert not naive_fires, "range test unexpectedly fired"

    result = Periodicity(direction=Direction.EGRESS).run(_series(intervals), CTX)
    assert result is not None and result.score > 0.5


def test_persistent_connection_is_not_a_beacon():
    """The inverted-detector false positive, stated as a test.

    A 30-second poller sampling a long-lived connection sees that connection
    present at every poll, with near-zero variance, and calls it a beacon.
    Burst-level observation of the same connection produces whatever the
    application actually did — here, irregular interactive traffic — and must
    not score as periodic.
    """
    rng = random.Random(SEED)
    bursty = [rng.expovariate(1 / 3.0) for _ in range(60)]
    result = Periodicity(direction=Direction.EGRESS).run(_series(bursty), CTX)
    assert result is None or result.score < 0.5


def test_in_connection_heartbeat_matches_reconnect_beacon():
    """Both modern and classic beacon shapes must land on the same series.

    A websocket implant heartbeating inside one TLS connection and a
    reconnect beacon opening a connection per callback are the same
    behaviour at the burst level, and the primitive must not be able to tell
    them apart.
    """
    rng_a = random.Random(SEED)
    rng_b = random.Random(SEED)
    prim = Periodicity(direction=Direction.EGRESS)

    reconnect = prim.run(_series(_jittered(60.0, 0.2, 30, rng_a)), CTX)
    in_conn = prim.run(_series(_jittered(60.0, 0.2, 30, rng_b)), CTX)

    assert reconnect is not None and in_conn is not None
    assert abs(reconnect.score - in_conn.score) < 1e-9
    assert abs(reconnect.features["period_s"] - in_conn.features["period_s"]) < 1e-9


def test_short_series_declines_to_answer():
    """Too few samples must yield None, never a confident-looking number."""
    assert Periodicity().run(_series([60.0, 60.0]), CTX) is None


def test_degenerate_series_declines_to_answer():
    """Identical timestamps are degenerate, not perfectly periodic."""
    assert Periodicity().run(_series([0.0] * 20), CTX) is None


def test_burstiness_signs_are_right():
    rng = random.Random(SEED)
    regular = Burstiness().run(_series([60.0] * 30), CTX)
    poisson = Burstiness().run(
        _series([rng.expovariate(1 / 60.0) for _ in range(200)]), CTX
    )
    assert regular is not None and poisson is not None
    assert regular.features["burstiness"] < -0.9      # perfectly periodic
    assert abs(poisson.features["burstiness"]) < 0.25  # memoryless


def test_burst_assembler_merges_segments_and_splits_messages():
    """Segmentation must not manufacture a cadence.

    Three TCP segments of one application message 5ms apart are one
    Observation; the next message 60s later is a second one.
    """
    asm = BurstAssembler(gap_s=0.050)
    emitted = []
    for i in range(3):
        o = asm.feed(
            ts=1000.0 + i * 0.005, channel=CHANNEL, direction=Direction.EGRESS,
            payload_len=1400, wire_len=1452, kind="tcp_burst", source="t.pcap",
            frame=i + 1, stream=7,
        )
        if o:
            emitted.append(o)
    o = asm.feed(
        ts=1060.0, channel=CHANNEL, direction=Direction.EGRESS,
        payload_len=1400, wire_len=1452, kind="tcp_burst", source="t.pcap",
        frame=4, stream=7,
    )
    if o:
        emitted.append(o)
    emitted.extend(asm.flush())

    assert len(emitted) == 2, f"expected 2 bursts, got {len(emitted)}"
    first = emitted[0]
    assert first.size == 4200          # three segments merged
    assert first.ts == 1000.0          # timestamped at first packet
    assert first.locus.display_filter() == "tcp.stream eq 7"
    assert emitted[1].ts - first.ts == 60.0


def test_narrative_citations_are_verified_against_evidence():
    """A narrative citing a feature that was never computed is rejected."""
    from core.model import Evidence, Narrative

    result = Periodicity(direction=Direction.EGRESS).run(
        _series([60.0, 59.0, 61.0, 60.0, 59.5, 60.5, 60.0]), CTX
    )
    assert result is not None
    evidence = Evidence(
        channel=CHANNEL, series_count=8, window=(0.0, 480.0), results=(result,)
    )

    honest = Narrative(
        finding_id="x", summary="s", reasoning="r",
        cited_features=("periodicity.period_s",),
    )
    assert honest.verify_against(evidence)[0]

    invented = Narrative(
        finding_id="x", summary="s", reasoning="r",
        cited_features=("periodicity.malware_family",),
    )
    ok, unknown = invented.verify_against(evidence)
    assert not ok and unknown == ("periodicity.malware_family",)


# --------------------------------------------------------------------------


def report():
    """Print the separation table. Run directly, not via pytest."""
    rng = random.Random(SEED)
    prim = Periodicity(direction=Direction.EGRESS)
    jit = Jitter(direction=Direction.EGRESS)

    rows = []
    for label, intervals in [
        ("beacon  60s, jitter  0%", _jittered(60.0, 0.00, 40, rng)),
        ("beacon  60s, jitter 20%", _jittered(60.0, 0.20, 40, rng)),
        ("beacon  60s, jitter 50%", _jittered(60.0, 0.50, 40, rng)),
        ("beacon  60s, jitter 90%", _jittered(60.0, 0.90, 40, rng)),
        ("exact poller (cron 300s)", [300.0] * 40),
        ("interactive / bursty", [rng.expovariate(1 / 3.0) for _ in range(40)]),
        ("unstructured, same rate", [rng.expovariate(1 / 60.0) for _ in range(40)]),
    ]:
        s = _series(intervals)
        p = prim.run(s, CTX)
        j = jit.run(s, CTX)
        rows.append((
            label,
            f"{p.score:.3f}" if p else "  -  ",
            f"{p.features['period_s']:7.1f}" if p else "    -  ",
            f"{p.features['interval_mad_ratio']:.3f}" if p else "  -  ",
            f"{j.features['implied_jitter_pct']:5.1f}%" if j else "   -  ",
        ))

    width = max(len(r[0]) for r in rows)
    print(f"\n{'series':<{width}}  period  MAD/med  implied   PERIODICITY")
    print("-" * (width + 42))
    for label, score, period, ratio, jitter in rows:
        print(f"{label:<{width}}  {period}  {ratio}   {jitter}      {score}")
    print()


def _run_all():
    """Stdlib test runner — core/ has no third-party dependency and neither
    does its test suite, so this stays runnable on a bare interpreter."""
    import traceback

    tests = sorted(
        (name, fn) for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
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
    import sys

    report()
    sys.exit(1 if _run_all() else 0)
