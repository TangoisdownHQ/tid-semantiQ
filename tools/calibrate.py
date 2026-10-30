"""A calibration harness: detection rate per jitter level, and false positives.

The README is candid that nothing in this repository is a detection rate —
the weights in `core/primitives/` are reasoned, not fitted. This turns that
honesty into a measurement you can run. It does NOT need Sliver or Havoc in a
lab: it synthesises the two things a beacon detector lives or dies on and runs
them through the REAL scorer, unchanged.

  - a beacon at a controlled jitter level, to a destination the baseline has
    never seen (so rarity can speak), and
  - benign background — exact-interval pollers and irregular browsing to a
    handful of destinations every host contacts, so those are prevalent and
    the rarity gate should suppress them.

It measures two numbers, kept strictly apart because they answer different
questions:

  DETECTION — of N beacon trials at a given jitter, how many fired a beacon
  rule. Swept across 0 / 20 / 50 / 90% jitter, which is the curve that says
  whether the detector survives the evasion technique it is named against.

  FALSE POSITIVES — beacon/exfil rules firing on the benign background,
  judged against the warmed baseline. The thing a cold baseline floods and a
  warm one should not.

WHY THIS IS NOT A TEST. The tests assert fixed thresholds hold; this reports
a curve and lets you move a threshold and watch it move. `--sweep` re-runs the
whole measurement across a range of one tunable, which is exactly the refit
loop the README describes — `periodicity.dispersion_decay`, `size_floor`,
`count_saturation` — without a patch.

HONEST ABOUT ITS OWN LIMITS. Synthetic traffic is not real C2: the jitter is
uniform where a real implant's may be Gaussian or patterned, and the
background is modelled, not captured. A number here is a property of the
scorer against THIS model, and the harness says so in its own output. Pair it
with `measure_false_positives.py` on a real capture for the other half.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from core.baseline import SqliteBaseline
from core.model import Channel, Context, Direction, Entity, Locus, Observation
from core.score import run
from ontology import ONTOLOGIES

import tempfile

#: Jitter levels to sweep, as a percentage of the nominal period. These are
#: the four the README names, and the ones C2 frameworks expose as a knob.
JITTER_LEVELS = (0, 20, 50, 90)

#: The rules whose firing counts as a beacon detection / a beacon-class FP.
_BEACON_RULES = ("net.beacon.periodic_callback", "net.beacon.low_and_slow")

_BASE_TS = 1_700_000_000.0


def _obs(ts: float, channel: Channel, size: int,
         direction: Direction = Direction.EGRESS) -> Observation:
    return Observation(
        ts=ts, channel=channel, direction=direction, size=size,
        kind="tcp_burst", attrs={"encrypted": True},
        locus=Locus(source="calibrate", frames=(int(ts),)),
    )


def _channel(host: str, dest: str, dport: str = "443") -> Channel:
    return Channel(
        domain="net",
        dims={"proto": "tcp", "dport": dport},
        initiator=Entity("ip", host, labels={"private": True}),
        responder=Entity("ip", dest, labels={"private": False}),
    )


def _beacon(rng: random.Random, host: str, dest: str, period_s: float,
            jitter_pct: int, callbacks: int, size: int = 256) -> List[Observation]:
    """One beacon channel: `callbacks` check-ins at `period_s`, each interval
    perturbed by uniform +/- jitter_pct.

    ONE observation per callback, matching the pipeline. On a real capture a
    request and its reply are burst-assembled into a single Observation; two
    observations 0.05s apart would instead hand Periodicity a bimodal
    interval sequence [0.05, period, 0.05, ...] and score a perfect beacon as
    noise — the harness measuring an artefact of its own synthesis, not the
    scorer. Each callback is therefore one exchange, as the assembler would
    emit."""
    channel = _channel(host, dest)
    out: List[Observation] = []
    ts = _BASE_TS
    span = period_s * jitter_pct / 100.0
    for _ in range(callbacks):
        out.append(_obs(ts, channel, size, Direction.EGRESS))
        ts += max(1.0, period_s + rng.uniform(-span, span))
    return out


def _benign(rng: random.Random, hosts: int, dests: List[str],
            span_s: float) -> List[Observation]:
    """Background every host produces: an exact-interval poller to each shared
    destination (the update-checker shape that scores 1.000 on periodicity and
    MUST be suppressed), plus irregular browsing bursts. Shared destinations
    across hosts are what make them prevalent."""
    out: List[Observation] = []
    for h in range(hosts):
        host = f"10.0.{h // 254}.{h % 254 + 1}"
        for d, dest in enumerate(dests):
            # Exact-interval poller — the hardest benign case: it scores a
            # perfect 1.000 on periodicity, so ONLY rarity can suppress it,
            # which is exactly the claim under test. One exchange per poll,
            # like the assembler (see _beacon).
            period = 60.0 * (d + 1)
            ts = _BASE_TS
            while ts < _BASE_TS + span_s:
                out.append(_obs(ts, _channel(host, dest), 512))
                ts += period
            # irregular browsing to the same prevalent destination
            for _ in range(rng.randint(5, 15)):
                t = _BASE_TS + rng.uniform(0, span_s)
                out.append(_obs(t, _channel(host, dest), rng.randint(200, 1500)))
    return out


def _series(observations: List[Observation]):
    return list(group_into_series(observations, min_observations=2))


def _ctx(series, baseline, config: Dict) -> Context:
    now = max((s.end or 0.0) for s in series) if series else _BASE_TS
    return Context(now=now, baseline=baseline, config=config)


def _warm(baseline, rng: random.Random, hosts: int, dests: List[str],
          span_s: float, config: Dict) -> None:
    series = _series(_benign(rng, hosts, dests, span_s))
    run(series, ONTOLOGIES, _ctx(series, baseline, config))   # record=True


def _beacon_fired(baseline, rng, period_s, jitter, callbacks, dest,
                  config) -> bool:
    series = _series(_beacon(rng, "10.9.9.9", dest, period_s, jitter, callbacks))
    findings, _ = run(series, ONTOLOGIES, _ctx(series, baseline, config),
                      record=False)
    return any(f.rule_id in _BEACON_RULES for f in findings)


def _false_positives(baseline, rng, hosts, dests, span_s,
                     config) -> Tuple[int, int]:
    series = _series(_benign(rng, hosts, dests, span_s))
    findings, _ = run(series, ONTOLOGIES, _ctx(series, baseline, config),
                      record=False)
    fp = sum(1 for f in findings if f.rule_id in _BEACON_RULES)
    return fp, hosts


def _measure(config: Dict, args, seed: int) -> Dict:
    """One full measurement at a given tunable config. Returns detection per
    jitter level and the benign false-positive count."""
    rng = random.Random(seed)
    dests = [f"203.0.113.{i + 1}" for i in range(args.benign_dests)]
    with tempfile.TemporaryDirectory() as d:
        baseline = SqliteBaseline(Path(d) / "cal.db")
        _warm(baseline, rng, args.hosts, dests, args.span * 60, config)

        detection: Dict[int, float] = {}
        for jitter in JITTER_LEVELS:
            hits = 0
            for trial in range(args.trials):
                # a fresh, novel destination per trial, never in the baseline
                dest = f"198.51.100.{trial % 254 + 1}"
                if _beacon_fired(baseline, rng, args.period, jitter,
                                 args.callbacks, dest, config):
                    hits += 1
            detection[jitter] = hits / args.trials

        fp, hosts = _false_positives(baseline, rng, args.hosts, dests,
                                     args.span * 60, config)
    return {"detection": detection, "fp": fp, "hosts": hosts}


def _print_measurement(result: Dict, args) -> None:
    print("  jitter   detection")
    for jitter in JITTER_LEVELS:
        rate = result["detection"][jitter]
        bar = "█" * round(rate * 24)
        print(f"  {jitter:>4}%   {rate:>5.0%}  {bar}")
    span_h = args.span / 60.0
    fp_rate = result["fp"] / max(1e-9, result["hosts"] * span_h)
    print(f"\n  false positives (benign background): {result['fp']} over "
          f"{result['hosts']} host(s) × {span_h:.1f}h")
    print(f"                                       = {fp_rate:.2f} "
          "beacon-class FP per host per hour")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detection-rate-per-jitter and false-positive harness "
                    "for the beacon detector, against synthetic traffic.")
    parser.add_argument("--trials", type=int, default=40,
                        help="beacon trials per jitter level (default 40)")
    parser.add_argument("--hosts", type=int, default=20,
                        help="benign background hosts (default 20)")
    parser.add_argument("--benign-dests", type=int, default=4,
                        help="shared (prevalent) destinations (default 4)")
    parser.add_argument("--period", type=float, default=60.0,
                        help="nominal beacon period in seconds (default 60)")
    parser.add_argument("--callbacks", type=int, default=30,
                        help="callbacks per beacon (default 30). Above "
                             "periodicity.count_saturation (20) on purpose: "
                             "below it the evidence-weight discount — a "
                             "separate, correct gate on thin evidence — "
                             "masks the jitter curve this is measuring. Lower "
                             "it to study the evidence-count gate instead.")
    parser.add_argument("--span", type=float, default=120.0,
                        help="benign background span in minutes (default 120)")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--sweep", metavar="KEY=LO:HI:STEP",
        help="re-run the whole measurement across a tunable range, e.g. "
             "periodicity.dispersion_decay=2:5:0.5 — the refit loop")
    parser.add_argument("--set", action="append", metavar="KEY=VALUE",
                        default=[], help="fix a tunable for every run")
    args = parser.parse_args()

    base_config: Dict = {}
    for pair in args.set:
        key, _, value = pair.partition("=")
        base_config[key] = float(value)

    print("tid-semantiQ calibration — SYNTHETIC traffic through the real scorer.")
    print("A number here is a property of the scorer against this model, not a")
    print("field detection rate; pair with measure_false_positives.py on real")
    print(f"traffic. seed={args.seed}, {args.trials} trials/level, "
          f"{args.hosts} benign hosts, period {args.period:g}s.\n")

    if not args.sweep:
        result = _measure(base_config, args, args.seed)
        _print_measurement(result, args)
        return 0

    key, _, rng_spec = args.sweep.partition("=")
    lo, hi, step = (float(x) for x in rng_spec.split(":"))
    print(f"SWEEP {key} from {lo:g} to {hi:g} step {step:g}\n")
    value = lo
    while value <= hi + 1e-9:
        config = dict(base_config)
        config[key] = value
        result = _measure(config, args, args.seed)
        det = " ".join(f"{j}%:{result['detection'][j]:.0%}"
                       for j in JITTER_LEVELS)
        print(f"  {key}={value:<6g}  detection[{det}]  "
              f"FP={result['fp']}")
        value += step
    print("\nRead the sweep as a trade: a smaller decay sharpens the periodicity")
    print("score (more detection at high jitter) but admits more benign pollers")
    print("(more FP). The right value is where detection holds and FP does not.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
