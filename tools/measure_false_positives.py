#!/usr/bin/env python3
"""Measure the false-positive rate on a real capture, by splitting it in two.

THE METHOD. Train the baseline on the first half of a capture, then judge the
second half. Same host, same network, same behaviour, no attacker — so every
finding that fires is a false positive BY CONSTRUCTION. No labelling, no
ground truth, no lab required: the capture labels itself.

That is the number this project has never had. Every figure quoted so far —
the 47-to-2 reduction, 98.4% detection at 20% jitter, ~1% on the timing
oracle — came from fixtures written to exercise the code. None of it says
what the tool does to an operator's inbox on a Tuesday.

WHAT IT CANNOT TELL YOU. Nothing about detection rate, because there is
nothing to detect. A tool that reports zero findings on everything would
score perfectly here. Read it alongside the synthetic detection figures, not
instead of them.

CAVEAT ON THE SPLIT. Behaviour drifts across a capture — a host browsing in
the first half and idle in the second produces novel channels in the second
through no fault of the tool. Findings gated on `rarity.novel` are therefore
reported separately, since "this channel is new" is trivially true for
anything the first half did not contain.

    python3 tools/measure_false_positives.py capture.pcapng
    python3 tools/measure_false_positives.py capture.pcapng --split 0.5
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capture.base import group_into_series
from capture.pcap import PcapSource
from core.baseline import SqliteBaseline
from core.model import Context, Observation
from core.score import run
from ontology import ONTOLOGIES


def _pruning_floors() -> Dict[str, int]:
    from inspectors import INSPECTOR_STACKS

    return {domain: 1 for domain, stack in INSPECTOR_STACKS.items() if stack}


def _split(observations: List[Observation], fraction: float):
    """Split by TIME, not by count.

    Splitting on observation count would put a burst of traffic entirely on
    one side and make the halves incomparable. The question is "what does the
    tool say about the second part of an hour given the first part", so the
    boundary has to be a clock.
    """
    start = min(o.ts for o in observations)
    end = max(o.ts for o in observations)
    boundary = start + (end - start) * fraction
    train = [o for o in observations if o.ts <= boundary]
    judge = [o for o in observations if o.ts > boundary]
    return train, judge, boundary - start, end - boundary


def _series(observations):
    return list(group_into_series(
        observations, min_observations=2, min_by_domain=_pruning_floors()
    ))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture")
    parser.add_argument("--split", type=float, default=0.5,
                        help="fraction of the capture used for training")
    parser.add_argument("--max-memory-mb", type=int, default=2048)
    args = parser.parse_args()

    if args.max_memory_mb:
        import resource
        limit = args.max_memory_mb * 1024 * 1024
        _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (limit, hard))

    path = Path(args.capture)
    if not path.exists():
        print(f"no such capture: {path}", file=sys.stderr)
        return 2

    source = PcapSource(path)
    observations = list(source.observations())
    if not observations:
        print("nothing decodable in the capture", file=sys.stderr)
        return 1

    train_obs, judge_obs, train_s, judge_s = _split(observations, args.split)
    train, judge = _series(train_obs), _series(judge_obs)

    print(f"capture   {path.name}")
    print(f"          {source.stats['frames']:,} frames -> "
          f"{len(observations):,} observations")
    print(f"train     {train_s / 60:.1f} min, {len(train_obs):,} obs, "
          f"{len(train)} channels")
    print(f"judge     {judge_s / 60:.1f} min, {len(judge_obs):,} obs, "
          f"{len(judge)} channels")

    with tempfile.TemporaryDirectory() as tmp:
        baseline = SqliteBaseline(Path(tmp) / "fp.db")

        train_now = max(s.end or 0.0 for s in train)
        ctx = Context(now=train_now, baseline=baseline)
        run(train, ONTOLOGIES, ctx)                 # learn
        # `now` must be the CAPTURE's clock, not wall-clock — otherwise a
        # capture from last year reports a year of history. Same bug as
        # Context.now, in the reporting path this time.
        print(f"baseline  {baseline.describe_denominator(now=train_now)}")

        judge_now = max(s.end or 0.0 for s in judge)
        ctx = Context(now=judge_now, baseline=baseline)
        findings, evidences = run(judge, ONTOLOGIES, ctx, record=False)

    print()
    hosts = len({
        s.channel.initiator.value for s in judge if s.channel.initiator
    })
    per_host_hour = (
        len(findings) / max(1e-9, hosts * (judge_s / 3600.0))
    )
    print(f"FALSE POSITIVES  {len(findings)} over {judge_s / 60:.1f} min "
          f"across {hosts} host(s)")
    print(f"                 = {per_host_hour:.1f} per host per hour")

    # WHETHER THE ZERO MEANS ANYTHING.
    #
    # A clean result is only informative if the analyses could have spoken.
    # Ten minutes of traffic cannot evidence a 60-second cadence — not
    # because the tool is well calibrated but because `Periodicity` needs six
    # observations and nothing accumulated them. Reporting how far each
    # primitive got turns an uninterpretable zero into a bounded one.
    produced: Counter = Counter()
    headroom: Dict[str, float] = {}
    for evidence in evidences:
        for result in evidence.results:
            if result.name == "_scoring":
                continue
            produced[result.name] += 1
            headroom[result.name] = max(
                headroom.get(result.name, 0.0), result.score
            )
        for inspection in evidence.inspections:
            produced[inspection.name] += 1
            headroom[inspection.name] = max(
                headroom.get(inspection.name, 0.0), inspection.score
            )

    print()
    print(f"assessability — of {len(evidences)} channels judged:")
    if not produced:
        print("   nothing produced a result at all; this measurement is vacuous")
    for name, count in produced.most_common():
        print(f"   {count:>5} channels  {name:<28} "
              f"best score {headroom[name]:.2f}")

    if not findings:
        print()
        print("Zero false positives. Read it against the table above: a zero")
        print("is only meaningful where a primitive got close to its")
        print("threshold and still did not fire. Where the best score is far")
        print("below any rule's gate, nothing was measurable and the zero")
        print("says nothing about calibration.")
        return 0

    print()
    novel_gated: List = []
    other: List = []
    for finding in findings:
        if finding.evidence.feature("rarity", "novel", 0.0) == 1.0:
            novel_gated.append(finding)
        else:
            other.append(finding)

    for label, group in (("gated on novelty", novel_gated),
                         ("not novelty-gated", other)):
        if not group:
            continue
        print(f"{label}: {len(group)}")
        for rule, count in Counter(f.rule_id for f in group).most_common():
            print(f"   {count:>4}  {rule}")
    if novel_gated:
        print()
        print("Novelty-gated findings are the weaker half of this measurement:")
        print("a channel absent from the first half is trivially 'new' in the")
        print("second, through no fault of the tool.")

    print()
    print("worst five, with the arithmetic:")
    for finding in findings[:5]:
        channel = finding.channel
        where = (
            f"{channel.initiator.value} -> {channel.responder.value}"
            if channel.initiator and channel.responder else channel.domain
        )
        print(f"  [{finding.severity.value.upper():<8}] {finding.confidence:.2f}  "
              f"{finding.rule_id}")
        print(f"             {where}  {dict(channel.dims)}")
        scoring = finding.evidence.by_name("_scoring")
        if scoring and scoring.notes:
            print(f"             {' | '.join(scoring.notes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
