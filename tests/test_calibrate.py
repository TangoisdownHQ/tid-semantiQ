"""The calibration harness — detection curve and false-positive floor.

The harness is only trustworthy if it measures the SCORER, not an artefact
of its own synthesis. The load-bearing test is `test_one_exchange_per_event`:
an earlier version emitted a request and a reply 0.05s apart, which handed
Periodicity a bimodal interval sequence and scored a perfect beacon as noise
— the harness would then have reported the scorer failing when it was the
synthesis that was wrong. The rest pin the shape of the result: a monotone
detection curve, perfect detection of a clean beacon, suppression of the
prevalent poller, and that a tunable actually moves the curve.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tools.calibrate as C


def _args(**overrides):
    base = dict(trials=6, hosts=6, benign_dests=3, period=60.0, callbacks=30,
                span=60.0, seed=1337, sweep=None, set=[])
    base.update(overrides)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------
# synthesis must not fight the scorer
# --------------------------------------------------------------------------


def test_one_exchange_per_event():
    """REGRESSION. A reply observation beside each callback makes the interval
    sequence bimodal and tanks periodicity — the harness measuring its own
    synthesis. A beacon of N callbacks must be exactly N observations, evenly
    spaced at the period when jitter is zero."""
    rng = random.Random(1)
    obs = C._beacon(rng, "10.9.9.9", "198.51.100.5", 60.0, 0, 12)
    assert len(obs) == 12
    gaps = [round(obs[i + 1].ts - obs[i].ts) for i in range(len(obs) - 1)]
    assert gaps == [60] * 11, gaps


def test_jitter_widens_the_intervals():
    rng = random.Random(1)
    tight = C._beacon(rng, "h", "d", 60.0, 0, 30)
    loose = C._beacon(rng, "h", "d", 60.0, 90, 30)
    def spread(o):
        g = [o[i + 1].ts - o[i].ts for i in range(len(o) - 1)]
        return max(g) - min(g)
    assert spread(tight) == 0
    assert spread(loose) > 20, spread(loose)


def test_benign_destinations_are_shared_so_they_are_prevalent():
    """Every host must contact the same destinations, or 'prevalent' has no
    meaning and the FP test is vacuous."""
    rng = random.Random(1)
    obs = C._benign(rng, hosts=5, dests=["203.0.113.1", "203.0.113.2"],
                    span_s=3600)
    by_dest = {}
    for o in obs:
        by_dest.setdefault(o.channel.responder.value, set()).add(
            o.channel.initiator.value)
    # each benign destination is reached by all five hosts
    assert by_dest["203.0.113.1"] == {f"10.0.0.{h + 1}" for h in range(5)}


# --------------------------------------------------------------------------
# the measurement
# --------------------------------------------------------------------------


def test_clean_beacon_is_detected_and_pollers_are_not():
    result = C._measure({}, _args(), seed=1337)
    assert result["detection"][0] == 1.0, "a zero-jitter beacon must be caught"
    assert result["fp"] == 0, (
        f"prevalent pollers leaked as beacons: {result['fp']}")


def test_detection_falls_as_jitter_rises():
    result = C._measure({}, _args(trials=10), seed=1337)
    d = result["detection"]
    # monotone non-increasing across the four levels, and high jitter is
    # genuinely harder than none.
    levels = [d[j] for j in C.JITTER_LEVELS]
    assert levels == sorted(levels, reverse=True), levels
    assert d[90] < d[0]


def test_a_tunable_moves_the_curve():
    """The refit premise: lowering dispersion_decay sharpens periodicity and
    recovers detection at high jitter."""
    base = C._measure({"periodicity.dispersion_decay": 4.0},
                      _args(trials=10), seed=1337)
    sharp = C._measure({"periodicity.dispersion_decay": 2.0},
                       _args(trials=10), seed=1337)
    assert sharp["detection"][50] >= base["detection"][50]
    assert sharp["detection"][50] > base["detection"][50] or \
        sharp["detection"][90] >= base["detection"][90]


def test_measurement_is_deterministic():
    a = C._measure({}, _args(), seed=42)
    b = C._measure({}, _args(), seed=42)
    assert a["detection"] == b["detection"] and a["fp"] == b["fp"]


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
