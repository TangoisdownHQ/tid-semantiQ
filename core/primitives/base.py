"""The primitive interface.

A primitive answers exactly one question about a `Series`, in a way that does
not depend on which domain the Series came from. There are eight:

    periodicity   is there a repeating cadence, and what is it?
    jitter        how much deliberate randomisation sits on that cadence?
    burstiness    is the arrival process clustered, Poisson, or regular?
    asymmetry     which way does the volume flow, and how hard?
    rarity        how new and how uncommon is this channel?          [needs baseline]
    entropy       how compressible is the payload?                   [cleartext only]
    fanout        how many distinct peers/ports/names, per source?
    sequence      does the exchange order violate the protocol grammar?  [needs grammar]

The first four are pure functions of a Series and nothing else. `rarity` needs
a `BaselineStore`, `entropy` needs payload bytes, and `sequence` needs a
grammar from the ontology — in all three cases the dependency arrives through
`Context` or through the constructor, never through a global.

WHY THIS IS THE REUSABLE CORE. Parsers share no code across domains: a TLS
ClientHello parser and a CAN frame decoder have nothing in common. The
statistics do. Detecting a repeating cadence in a 60-second TLS callback is
the same computation as detecting it in a MAVLink heartbeat, a Modbus poll
cycle, a CAN frame id, or a BLE advertising interval. Industrial and avionics
buses are in fact the easiest case, because they are periodic by design and
deviation is correspondingly meaningful.

APPLICABILITY. A primitive that cannot answer its question must return None,
never a misleading number. Entropy over TLS ciphertext is the canonical trap:
it is ~8 bits/byte by construction, so reporting it as a finding is reporting
that encryption works. `applies_to` exists so that trap is a declaration
rather than a comment.
"""

from __future__ import annotations

import statistics
from abc import ABC, abstractmethod
from typing import Mapping, Optional, Sequence, Tuple

from core.model import Context, PrimitiveResult, Series

__all__ = ["Primitive", "clamp", "median", "mad", "mad_ratio", "bowley_skew", "saturating"]


# --------------------------------------------------------------------------
# shared statistics
# --------------------------------------------------------------------------
#
# Deliberately stdlib-only. core/ has no third-party dependency, so primitives
# are portable, trivially testable, and cheap to reimplement in another
# language later if the capture loop ever moves to Rust.


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def median(xs: Sequence[float]) -> float:
    return statistics.median(xs)


def mad(xs: Sequence[float]) -> float:
    """Median absolute deviation.

    This replaces the `max(xs) - min(xs)` spread that naive beacon detectors
    use. The difference is not cosmetic: range is destroyed by a single
    outlier interval and collapses the moment any jitter is applied, whereas
    MAD degrades smoothly. A beacon with 50% jitter is invisible to a range
    test and scores ~0.8 under MAD.
    """
    m = statistics.median(xs)
    return statistics.median([abs(x - m) for x in xs])


def mad_ratio(xs: Sequence[float]) -> Optional[float]:
    """MAD normalised by the median — a scale-free dispersion measure.

    0.0 for a perfectly regular series; ~0.25 for uniform +/-50% jitter;
    ~0.6-0.7 for an exponential (memoryless, i.e. unstructured) arrival
    process. Returns None when the median is zero, where the ratio is
    undefined.
    """
    m = statistics.median(xs)
    if m <= 0:
        return None
    return mad(xs) / m


def bowley_skew(xs: Sequence[float]) -> float:
    """Quartile-based skewness, in [-1, 1]. 0 means symmetric.

    Quartile skew rather than the third moment because it is bounded and
    outlier-resistant, which matters when a single retransmit or a missed
    callback would otherwise dominate.
    """
    if len(xs) < 4:
        return 0.0
    q1, q2, q3 = statistics.quantiles(sorted(xs), n=4, method="inclusive")
    spread = q3 - q1
    if spread <= 0:
        return 0.0
    return (q3 + q1 - 2 * q2) / spread


def saturating(value: float, saturation: float) -> float:
    """Map a count onto 0..1, reaching 1 at `saturation`.

    Used so that a channel seen six times and one seen six hundred times are
    not treated as equally well-evidenced.
    """
    if saturation <= 0:
        return 1.0
    return clamp(value / saturation)


# --------------------------------------------------------------------------
# the interface
# --------------------------------------------------------------------------


class Primitive(ABC):
    """One domain-agnostic question about a Series.

    Subclasses declare `name`, declare what they need, and implement
    `compute`. They must not mutate the Series, must not touch the network or
    the filesystem, and must be deterministic given (Series, Context) — the
    scorer memoises on that pair and the test suite depends on it.
    """

    #: stable identifier; appears in the evidence ledger and in narrative
    #: citations as "<name>.<feature>", so changing it is a breaking change
    name: str = ""

    #: minimum observations before the answer is statistically meaningful.
    #: Below this, compute() must return None rather than a noisy score.
    min_observations: int = 2

    #: Observation fields that must be populated for this primitive to run.
    #: Checked by `applies_to`; lets a domain plugin that cannot supply
    #: payloads skip entropy automatically instead of failing at runtime.
    requires_fields: Tuple[str, ...] = ()

    #: True if the primitive needs a BaselineStore in Context.
    requires_baseline: bool = False

    # -- applicability -----------------------------------------------------

    def applies_to(self, series: Series, ctx: Context) -> bool:
        """Cheap gate, run before `compute`.

        Override to add domain or mode conditions — entropy, for instance,
        returns False in passive mode on an encrypted channel, because the
        answer would be true and worthless.
        """
        if series.count < self.min_observations:
            return False
        if self.requires_baseline and ctx.baseline is None:
            return False
        for fieldname in self.requires_fields:
            if any(getattr(o, fieldname, None) is None for o in series):
                return False
        return True

    # -- the computation ---------------------------------------------------

    @abstractmethod
    def compute(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        """Answer this primitive's question, or return None if it cannot.

        Returning None is a first-class outcome and must be used whenever the
        inputs are too few, degenerate (all-identical timestamps), or outside
        the primitive's competence. The scorer treats a missing result as
        absent evidence, which is correct, rather than as a zero score, which
        would be a claim.
        """
        raise NotImplementedError

    # -- convenience -------------------------------------------------------

    def run(self, series: Series, ctx: Context) -> Optional[PrimitiveResult]:
        """applies_to + compute. This is what the pipeline calls."""
        if not self.applies_to(series, ctx):
            return None
        return self.compute(series, ctx)

    def _result(
        self,
        score: float,
        features: Mapping[str, float],
        sample_size: int,
        method: str = "",
        notes: Tuple[str, ...] = (),
    ) -> PrimitiveResult:
        return PrimitiveResult(
            name=self.name,
            score=clamp(score),
            features={k: float(v) for k, v in features.items()},
            sample_size=sample_size,
            method=method,
            notes=notes,
        )

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"<Primitive {self.name}>"
