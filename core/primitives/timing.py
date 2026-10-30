"""Timing primitives: periodicity, jitter, burstiness.

All three consume the same input — the inter-arrival series — and answer
different questions about it. They are separated because the scorer needs to
weigh them independently: "there is a cadence", "the cadence is deliberately
randomised", and "arrivals are clustered" are three different claims and
collapsing them loses the discrimination that keeps false positives down.

Periodicity is the reference implementation for the whole primitive
interface, and it is the load-bearing detector for the first domain, so it is
the one worth reading closely.
"""

from __future__ import annotations

from typing import Optional

from core.model import Context, Direction, PrimitiveResult, Series
from core.primitives.base import (
    Primitive,
    bowley_skew,
    clamp,
    mad,
    mad_ratio,
    median,
    saturating,
)

__all__ = ["Periodicity", "Jitter", "Burstiness"]


def _dispersion_score(ratio: float, decay: float) -> float:
    """Map a MAD/median dispersion ratio onto 0..1 regularity.

    exp(-k * ratio), not 1 - ratio. The linear mapping is far too generous
    at the noisy end: a memoryless arrival process has MAD/median around
    0.67, which linearly scores 0.33 — high enough that ordinary traffic
    lands in the same band as a jittered beacon and the detector is useless.
    Exponential decay puts the same series near 0.13 while leaving a tight
    cadence at ~1.0. `decay` is the knob that sets how fast regularity is
    forgiven, and it is the first parameter to refit against lab data.
    """
    import math

    return clamp(math.exp(-decay * max(0.0, ratio)))


class Periodicity(Primitive):
    """Is there a repeating cadence on this channel, and what is it?

    METHOD. A composite of four normalised components, following the approach
    published for RITA's beacon scoring (reimplemented from the described
    method — RITA itself is GPLv3 and no code is borrowed):

        timing dispersion   1 - MAD(intervals)/median(intervals)
        timing symmetry     1 - |bowley_skew(intervals)|
        size regularity     the same two measures over payload sizes
        evidence weight     saturating(observation count)

    Timing components are combined geometrically, so a series that is regular
    but badly skewed does not score well on dispersion alone. Size regularity
    is weighted lower than timing because TLS record padding, HTTP/2
    multiplexing, and QUIC all degrade size signal while leaving timing
    intact.

    WHY NOT RANGE. The naive test is `max(intervals) - min(intervals) <=
    tolerance`. It fails in both directions: one delayed callback destroys
    it, and any applied jitter defeats it outright. Every modern C2 framework
    ships a jitter setting. MAD degrades smoothly instead — see the
    separation table in docs/SPEC-observation.md.

    WHAT THIS SCORE IS NOT. A high score means "regular", not "malicious".
    Legitimate periodic traffic vastly outnumbers malicious periodic traffic
    on any real network — update checkers, telemetry agents, NTP, keepalives,
    CDN heartbeats. Suspicion is the scorer's job, and it comes from
    combining this with rarity, destination reputation, and process
    attribution. A deployment that alerts on periodicity alone will drown.

    CALIBRATION STATUS. The component weights below are reasoned, not yet
    empirically fitted. They must be refit against lab ground truth (C2 at
    0/20/50/90% jitter, plus a week of clean traffic as the false-positive
    denominator) before any of these numbers are quoted to anyone.
    """

    name = "periodicity"
    min_observations = 6          # 5 intervals: the floor for a stable MAD

    def __init__(
        self,
        direction: Optional[Direction] = None,
        group_attr: Optional[str] = None,
    ):
        """`direction` narrows the series before measuring.

        The network ontology instantiates this with EGRESS, because the
        callback cadence of a beacon is set by the client and inbound task
        responses arrive on the server's schedule, not the implant's.
        Broadcast domains (CAN, BLE) leave it None.

        `group_attr` measures each group's cadence separately and reports the
        strongest. REQUIRED when one channel interleaves several independent
        cadences, because the mixed interval series is then bimodal and
        scores near zero however regular each component is.

        Modbus made this concrete. A master polling two function codes 50ms
        apart on a 1s cycle produces intervals of 0.05, 0.95, 0.05, 0.95 —
        measured whole, that scored **0.001**, while a scanner firing evenly
        every 50ms scored **1.000**. Exactly backwards. Grouped by function
        code, each component is the clean 1s cadence it actually is.
        """
        self.direction = direction
        self.group_attr = group_attr

    def _narrow(self, series: Series) -> Series:
        if self.direction is not None:
            return series.filter(direction=self.direction)
        return series

    def applies_to(self, series: Series, ctx: Context) -> bool:
        series = self._narrow(series)
        if self.group_attr is not None:
            # Applicable if ANY group is long enough; `compute` decides.
            return any(
                group.count >= self.min_observations
                for group in series.group_by(self.group_attr).values()
            )
        return super().applies_to(series, ctx)

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        series = self._narrow(series)

        if self.group_attr is not None:
            best: Optional[PrimitiveResult] = None
            groups = series.group_by(self.group_attr)
            for label, group in groups.items():
                if group.count < self.min_observations:
                    continue
                result = self._measure(group, ctx)
                if result is None:
                    continue
                if best is None or result.score > best.score:
                    best = PrimitiveResult(
                        name=result.name,
                        score=result.score,
                        features={
                            **result.features,
                            "groups_measured": float(len(groups)),
                        },
                        sample_size=result.sample_size,
                        method=result.method + f"/by-{self.group_attr}",
                        notes=result.notes + (
                            f"strongest cadence is {self.group_attr}={label}; "
                            f"{len(groups)} group(s) present and measured "
                            "separately because a mixed series is bimodal",
                        ),
                    )
            return best

        return self._measure(series, ctx)

    def _measure(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        intervals = series.intervals()
        if len(intervals) < self.min_observations - 1:
            return None

        interval_median = median(intervals)
        dispersion_ratio = mad_ratio(intervals)
        if dispersion_ratio is None:
            # All observations share a timestamp, or the median interval is
            # zero. Degenerate, not periodic — say nothing rather than
            # reporting perfect regularity.
            return None

        decay = float(ctx.tunable("periodicity.dispersion_decay", 3.0))
        timing_dispersion = _dispersion_score(dispersion_ratio, decay)
        timing_symmetry = clamp(1.0 - abs(bowley_skew(intervals)))
        timing = (timing_dispersion * timing_symmetry) ** 0.5

        notes = []
        sizes = series.sizes()
        size_ratio = mad_ratio(sizes) if sizes else None
        if size_ratio is None:
            # Zero-length payloads (pure keepalives) or no size signal.
            # Treat size as neutral rather than as a zero, which would be a
            # claim we have not earned.
            size_component = None
            notes.append("size signal unavailable; scored on timing alone")
        else:
            size_dispersion = _dispersion_score(size_ratio, decay)
            size_symmetry = clamp(1.0 - abs(bowley_skew(sizes)))
            size_component = (size_dispersion * size_symmetry) ** 0.5

        saturation = float(ctx.tunable("periodicity.count_saturation", 20))
        evidence_weight = saturating(series.count, saturation)

        # Size enters as a bounded MULTIPLIER, not as an additive term.
        # Additive weighting gave every series a floor equal to the size
        # weight, which compressed the whole scale and left unstructured
        # traffic scoring 0.65 — the separation collapsed. As a multiplier in
        # [floor, 1.0], good size regularity can only confirm a cadence that
        # timing already found, and can never manufacture one.
        floor = float(ctx.tunable("periodicity.size_floor", 0.75))
        if size_component is None:
            shape = timing
            method = "mad-decay/timing-only"
        else:
            shape = timing * (floor + (1.0 - floor) * size_component)
            method = "mad-decay"

        score = evidence_weight * shape

        features = {
            "period_s": interval_median,
            "interval_mad_s": mad(intervals),
            "interval_mad_ratio": dispersion_ratio,
            "interval_skew": bowley_skew(intervals),
            "timing_regularity": timing,
            "observations": float(series.count),
            "span_s": series.duration,
            "evidence_weight": evidence_weight,
        }
        if size_component is not None:
            features["size_regularity"] = size_component
            features["median_size_bytes"] = median(sizes)

        return self._result(
            score=score,
            features=features,
            sample_size=len(intervals),
            method=method,
            notes=tuple(notes),
        )


class Jitter(Primitive):
    """How much randomisation sits on top of an existing cadence?

    Reported separately from periodicity because the two carry different
    information. Periodicity says a cadence exists; jitter characterises it.

    WHY IT IS WORTH A SEPARATE SCORE. Much legitimate periodic traffic is
    driven by timers that fire on exact intervals — cron, package managers,
    polling loops with a fixed sleep. C2 frameworks commonly randomise
    specifically to defeat regularity tests. So "regular but not exact" is a
    plausibly different population from "exact", and separating them gives
    the ranker a feature that may discriminate against the dominant
    false-positive class.

    This is a HYPOTHESIS, not an established rule. Plenty of legitimate
    software jitters deliberately to avoid thundering-herd effects, and some
    operators run zero jitter. The primitive therefore reports the measured
    ratio and does not encode a direction of suspicion; whether jitter is
    aggravating or mitigating is an ontology decision, and it must be settled
    empirically against lab data before it is weighted.

    `score` here is the *strength of the jitter signature*: it peaks in the
    band where a cadence is still clearly present but visibly randomised, and
    falls off at both ends (exact timers, and unstructured traffic).
    """

    name = "jitter"
    min_observations = 6

    def __init__(self, direction: Optional[Direction] = None):
        self.direction = direction

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        if self.direction is not None:
            series = series.filter(direction=self.direction)

        intervals = series.intervals()
        if len(intervals) < self.min_observations - 1:
            return None

        ratio = mad_ratio(intervals)
        if ratio is None:
            return None

        # An interval drawn uniformly from [p*(1-j), p] has MAD/median of
        # roughly j/4, so the observed ratio maps back to an approximate
        # jitter percentage. Reported as an estimate, with the derivation
        # stated, so nobody mistakes it for a parsed configuration value.
        implied_jitter = clamp(ratio * 4.0, 0.0, 1.0)

        # Signature strength: a triangular window peaking at the centre of
        # the "randomised but still cadenced" band.
        peak = float(ctx.tunable("jitter.peak_ratio", 0.15))
        width = float(ctx.tunable("jitter.band_width", 0.15))
        score = clamp(1.0 - abs(ratio - peak) / width)

        return self._result(
            score=score,
            features={
                "jitter_ratio": ratio,
                "implied_jitter_pct": implied_jitter * 100.0,
                "period_s": median(intervals),
            },
            sample_size=len(intervals),
            method="mad-ratio",
            notes=("implied_jitter_pct is derived from dispersion, not observed config",),
        )


class Burstiness(Primitive):
    """Is the arrival process clustered, memoryless, or regular?

    Uses the Goh-Barabasi burstiness parameter over inter-arrival times:

        B = (sigma - mu) / (sigma + mu),  in [-1, 1]

        -1   perfectly periodic
         0   Poisson / memoryless
        +1   strongly clustered

    Complements periodicity on the same input. It is the primitive that
    separates "silent then a burst of activity" — interactive operator
    sessions, staged exfiltration — from both steady beacons and ordinary
    traffic. `score` is the distance from Poisson, i.e. |B|, since structure
    in either direction is what is interesting; `features` carries the signed
    value so the ontology can tell the two apart.
    """

    name = "burstiness"
    min_observations = 6

    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        import statistics as _stats

        intervals = series.intervals()
        if len(intervals) < self.min_observations - 1:
            return None

        mu = _stats.fmean(intervals)
        if mu <= 0:
            return None
        sigma = _stats.pstdev(intervals)
        if sigma + mu == 0:
            return None

        b = (sigma - mu) / (sigma + mu)

        return self._result(
            score=clamp(abs(b)),
            features={
                "burstiness": b,
                "mean_interval_s": mu,
                "stdev_interval_s": sigma,
                "coefficient_of_variation": sigma / mu,
            },
            sample_size=len(intervals),
            method="goh-barabasi",
        )
