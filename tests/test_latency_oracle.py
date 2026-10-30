"""Response-time clustering — the timing oracle.

The riskiest analyzer in the tool, because latency is noisy in a way cookie
flags are not. Risk if it goes wrong is a plausible-looking finding nobody can
reproduce, which is worse than no analyzer.

So the negative tests dominate, and two of them encode specific failure modes
that were observed and fixed rather than imagined:

  test_unimodal_noise_never_fires          `separation / within_spread` is not
                                           a bimodality test — splitting any
                                           unimodal sample in half roughly
                                           halves the within-half MAD, so the
                                           ratio is inflated by construction.
  test_warm_up_exclusion_prevents_a_false_positive
                                           three connection warm-ups produced
                                           a 0.88-confidence "oracle" made
                                           entirely of TLS handshakes.

`test_measured_false_positive_rate` re-runs the measurement the thresholds
were chosen from, so drifting them has to be deliberate.
"""

from __future__ import annotations

import json
import math
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.har import HarSource
from core.baseline import NullBaseline
from core.model import (
    Channel,
    Context,
    Direction,
    Entity,
    Locus,
    Observation,
    Series,
)
from core.primitives.latency import (
    GAP_MULTIPLE,
    MIN_PER_CLUSTER,
    MIN_SAMPLES,
    ResponseTimeDifferential,
    best_two_split,
)
from core.score import analyse_series, run
from ontology import ONTOLOGIES
from tools.make_har import build_latency_har

HOST = "login.target-practice.test"
CHANNEL = Channel(
    domain="http",
    dims={"scheme": "https", "host": HOST},
    initiator=Entity("client", "local"),
    responder=Entity("host", HOST),
)
CTX = Context(now=0.0, baseline=NullBaseline(), mode="assisted")


def _series(times_ms, path="/login", statuses=None, warm_up=None) -> Series:
    statuses = statuses or ["401"] * len(times_ms)
    warm_up = warm_up or [False] * len(times_ms)
    return Series(CHANNEL, [
        Observation(
            ts=float(index),
            channel=CHANNEL,
            direction=Direction.INGRESS,
            size=100,
            kind="http_response",
            attrs={
                "path": path,
                "status": statuses[index],
                "elapsed_s": value / 1000.0,
                "connection_warm_up": warm_up[index],
            },
            locus=Locus("t.har", frames=(index + 1,), kind="har"),
        )
        for index, value in enumerate(times_ms)
    ])


def _from_fixture(**kwargs):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.har"
        path.write_text(json.dumps(build_latency_har(**kwargs)))
        series = list(group_into_series(
            HarSource(path).observations(), min_observations=1
        ))
        ctx = Context(
            now=max(s.end or 0.0 for s in series),
            baseline=NullBaseline(), mode="assisted",
        )
        return series, ctx


# --------------------------------------------------------------------------
# the splitter
# --------------------------------------------------------------------------


def test_split_declines_when_a_cluster_would_be_too_small():
    """Two points can always be peeled off and made to look like a cluster."""
    assert best_two_split([1, 2, 3, 4, 5]) is None          # n < 2*3
    assert best_two_split([1.0] * 6) is not None


def test_split_finds_the_obvious_boundary():
    index, low, high = best_two_split([10, 11, 12, 90, 91, 92])
    assert index == 3
    assert low == [10, 11, 12] and high == [90, 91, 92]


def test_split_is_order_independent():
    shuffled = [92, 10, 91, 12, 90, 11]
    index, low, high = best_two_split(shuffled)
    assert low == [10, 11, 12] and high == [90, 91, 92]


# --------------------------------------------------------------------------
# negative tests
# --------------------------------------------------------------------------


def test_unimodal_noise_never_fires():
    """The structural false positive.

    Uniform noise with no second population must stay silent. An earlier
    version using `separation / within_spread` alone fired on this, because
    that ratio measures nothing about bimodality — it is inflated by the act
    of splitting.
    """
    rng = random.Random(4242)
    fired = 0
    for _ in range(200):
        times = [rng.uniform(3, 27) for _ in range(14)]
        if ResponseTimeDifferential().run(_series(times), CTX) is not None:
            fired += 1
    assert fired == 0, f"{fired}/200 unimodal samples produced a finding"


def test_heavy_tailed_noise_rarely_fires():
    """Lognormal is the realistic latency shape and the hard case: a long
    right tail manufactures large gaps that mimic a second cluster. The gap
    test ALONE false-fired on 25% of these at n=25."""
    rng = random.Random(1234)
    fired = 0
    trials = 300
    for _ in range(trials):
        times = [math.exp(rng.gauss(math.log(15), 0.8)) for _ in range(20)]
        if ResponseTimeDifferential().run(_series(times), CTX) is not None:
            fired += 1
    rate = fired / trials
    assert rate < 0.05, f"heavy-tailed false positive rate {rate:.1%}"


def test_measured_false_positive_rate():
    """Re-runs the measurement the thresholds were chosen from.

    Documented worst case is ~1.6% per endpoint on heavy-tailed lognormal at
    n=10, against 98.4% detection of a genuine 80ms split. Asserted loosely
    so ordinary variance does not fail the suite, but tightly enough that
    moving a threshold has to be a decision.
    """
    rng = random.Random(99)
    shapes = {
        "uniform": lambda: rng.uniform(3, 27),
        "normal": lambda: max(0.1, rng.gauss(15, 5)),
        "lognormal": lambda: math.exp(rng.gauss(math.log(15), 0.45)),
    }
    for name, draw in shapes.items():
        fired = 0
        trials = 300
        for _ in range(trials):
            times = [draw() for _ in range(14)]
            if ResponseTimeDifferential().run(_series(times), CTX) is not None:
                fired += 1
        assert fired / trials < 0.03, f"{name}: {fired}/{trials} fired"


def test_sub_millisecond_difference_is_not_reported():
    """A real split that is far too small to measure across a network.

    An oracle an attacker cannot observe is not a finding, however clean the
    statistics. This gate is about remote reachability, not significance.
    """
    times = [1.00, 1.01, 1.02, 1.03, 1.60, 1.61, 1.62, 1.63, 1.64, 1.65]
    assert ResponseTimeDifferential().run(_series(times), CTX) is None


def test_too_few_samples_declines():
    times = [15, 16, 15, 95, 96, 95]       # clearly bimodal, but n < MIN_SAMPLES
    assert len(times) < MIN_SAMPLES
    assert ResponseTimeDifferential().run(_series(times), CTX) is None


def test_warm_up_exclusion_prevents_a_false_positive():
    """THE ONE THE FEATURE EXISTS FOR.

    A capture with no oracle but three connection warm-ups. Including them
    produced a 0.88-confidence finding with a 387ms separation — an "oracle"
    composed entirely of TLS handshakes. One spike could not do this
    (MIN_PER_CLUSTER is 3); three can, which is what a browser opening
    several connections to a host actually looks like.
    """
    series, ctx = _from_fixture(oracle=False, jitter_ms=4.0, connections=3)
    one = series[0]

    assert ResponseTimeDifferential().run(one, ctx) is None, (
        "warm-up exclusion failed to suppress the artefact"
    )

    # Point the detector at an attribute nobody sets, so nothing is excluded.
    unguarded = ResponseTimeDifferential(warm_up_attr="does_not_exist")
    leaked = unguarded.run(one, ctx)
    assert leaked is not None, (
        "the fixture no longer reproduces the warm-up artefact, so this test "
        "has stopped testing anything"
    )
    assert leaked.features["separation_ms"] > 100, (
        "the artefact should be a large apparent separation"
    )
    assert MIN_PER_CLUSTER == 3


def test_warm_up_count_is_reported():
    """Silent exclusion is its own failure mode — the operator needs to know
    samples were dropped."""
    series, ctx = _from_fixture(oracle=True, connections=3)
    result = ResponseTimeDifferential().run(series[0], ctx)
    assert result is not None
    assert result.features["warm_up_excluded"] == 3
    assert any("warm-up" in note for note in result.notes)


# --------------------------------------------------------------------------
# positive tests
# --------------------------------------------------------------------------


def test_hidden_oracle_is_detected():
    """Identical status and body, only the timing differs — the shape a
    partition-by-outcome design cannot see."""
    series, ctx = _from_fixture(oracle=True, aligned=False)
    result = ResponseTimeDifferential().run(series[0], ctx)
    assert result is not None
    assert result.score > 0.8
    assert result.features["status_aligned"] == 0.0
    assert 70 < result.features["separation_ms"] < 95
    assert result.features["fast_samples"] >= 3
    assert result.features["slow_samples"] >= 3


def test_visible_oracle_scores_lower_than_a_hidden_one():
    """When the clusters line up with status codes the difference is already
    apparent without measuring anything, so it must be pressed less hard."""
    hidden_series, ctx_h = _from_fixture(oracle=True, aligned=False)
    visible_series, ctx_v = _from_fixture(oracle=True, aligned=True)

    hidden = ResponseTimeDifferential().run(hidden_series[0], ctx_h)
    visible = ResponseTimeDifferential().run(visible_series[0], ctx_v)
    assert hidden is not None and visible is not None
    assert visible.features["status_aligned"] == 1.0
    assert visible.score < hidden.score


def test_rules_separate_hidden_from_visible():
    hidden_series, ctx_h = _from_fixture(oracle=True, aligned=False)
    findings, _ = run(hidden_series, ONTOLOGIES, ctx_h)
    rules = {f.rule_id for f in findings}
    assert "http.timing.hidden_differential" in rules
    assert "http.timing.visible_differential" not in rules

    visible_series, ctx_v = _from_fixture(oracle=True, aligned=True)
    findings, _ = run(visible_series, ONTOLOGIES, ctx_v)
    rules = {f.rule_id for f in findings}
    assert "http.timing.visible_differential" in rules
    assert "http.timing.hidden_differential" not in rules


def test_finding_states_it_is_unproven():
    """An unreplayed timing difference must never read as a confirmed bug."""
    series, ctx = _from_fixture(oracle=True, aligned=False)
    findings, _ = run(series, ONTOLOGIES, ctx)
    finding = next(
        f for f in findings if f.rule_id == "http.timing.hidden_differential"
    )
    assert finding.severity.value == "medium", (
        "an unconfirmed timing difference must not be HIGH or CRITICAL"
    )
    notes = " ".join(
        note
        for result in finding.evidence.results
        for note in result.notes
    )
    assert "NOT PROVEN" in notes
    assert "replay" in notes.lower()


def test_endpoints_are_judged_separately():
    """A slow endpoint and a fast endpoint are not an oracle. Clustering must
    happen within an endpoint, not across the host."""
    fast = _series([10 + i * 0.1 for i in range(10)], path="/fast")
    slow = _series([200 + i * 0.1 for i in range(10)], path="/slow")
    combined = Series(CHANNEL, list(fast) + list(slow))
    assert ResponseTimeDifferential().run(combined, CTX) is None


def test_multiplicity_tightens_with_more_endpoints():
    """Reporting the worst of k endpoints multiplies the per-endpoint false
    positive rate by roughly k, so the threshold must tighten as k grows."""
    rng = random.Random(777)
    many = []
    for endpoint in range(16):
        times = [rng.uniform(3, 27) for _ in range(12)]
        many.extend(_series(times, path=f"/e{endpoint}").observations)
    series = Series(CHANNEL, many)

    result = ResponseTimeDifferential().run(series, CTX)
    assert result is None, "16 noisy endpoints produced a finding"

    # And the correction is reported when a finding does emerge.
    oracle_series, ctx = _from_fixture(oracle=True)
    found = ResponseTimeDifferential().run(oracle_series[0], ctx)
    assert found is not None
    assert found.features["multiplicity_factor"] >= 1.0
    assert found.features["endpoints_considered"] >= 1


def test_thresholds_are_tunable():
    """A deployment with different noise characteristics must be able to
    retune without a patch."""
    times = [15.0, 15.2, 15.4, 15.6, 22.0, 22.2, 22.4, 22.6, 22.8, 23.0]
    strict = Context(now=0.0, baseline=NullBaseline(), mode="assisted")
    assert ResponseTimeDifferential().run(_series(times), strict) is not None

    loose = Context(
        now=0.0, baseline=NullBaseline(), mode="assisted",
        config={"timing.min_effect_ms": 50.0},
    )
    assert ResponseTimeDifferential().run(_series(times), loose) is None
    assert GAP_MULTIPLE > 1.0


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
