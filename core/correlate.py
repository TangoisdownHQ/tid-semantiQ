"""The correlator interface — relationships between channels.

The third and, by construction, LAST analyzer type. The three map onto the
three scopes a question can have, and there is no fourth:

    Primitive    one Series       behaviour over time on one channel
    Inspector    one Observation  content of one message
    Correlator   all Series       relationships BETWEEN channels

Some of the most valuable findings only exist at the third scope. "This
bearer token was minted by api.example.com and later sent to an analytics
host" is invisible to anything looking at one channel, because the finding IS
the pair. Same for third-party data flows and credential sharing across
hosts.

HOW IT STAYS COMPATIBLE. A correlator does not emit `Finding`s — that would
put a verdict outside the scorer and break invariant I2. It emits
`(Channel, InspectionResult)` pairs, attributing each to the channel where
the problem is actionable, and those merge into that channel's `Evidence`
before the rules run. So correlation findings are scored, titled, and
redacted by exactly the same path as everything else.

Attribution matters for triage: a leaked credential is attributed to the
channel that RECEIVED it, because that is the host that should not have it
and the request a triager needs to see.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Sequence, Tuple

from core.model import Channel, Context, InspectionResult, Observation, Series

__all__ = ["Correlator", "run_correlators", "CorrelationOutput"]


CorrelationOutput = Tuple[Channel, InspectionResult]


class Correlator(ABC):
    """One question about how channels relate to each other.

    Same discipline as the other two: no network, no filesystem, no globals,
    deterministic, and emit nothing when there is nothing to say.

    Correlators see every observation in the capture, including unredacted
    values — they have to, since matching a credential across hosts means
    comparing the credential. They must put secrets in declared
    `secret_facts` so masking still happens on output.
    """

    name: str = ""

    #: Channel domains this correlator reads. Empty means all.
    domains: Tuple[str, ...] = ()

    @abstractmethod
    def correlate(
        self, series: Sequence[Series], ctx: Context
    ) -> Iterable[CorrelationOutput]:
        raise NotImplementedError

    def relevant(self, series: Sequence[Series]) -> List[Series]:
        if not self.domains:
            return list(series)
        return [s for s in series if s.channel.domain in self.domains]

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"<Correlator {self.name}>"


def run_correlators(
    series: Sequence[Series],
    correlators: Sequence[Correlator],
    ctx: Context,
) -> Dict[str, List[InspectionResult]]:
    """Run every correlator, grouped by the channel key each result targets.

    Returns a map so the caller can merge results into the right `Evidence`
    without a second pass over the series list.
    """
    out: Dict[str, List[InspectionResult]] = {}
    for correlator in correlators:
        for channel, result in correlator.correlate(series, ctx):
            out.setdefault(channel.key, []).append(result)
    return out


def observations_of(series: Sequence[Series]) -> Iterable[Tuple[Series, Observation]]:
    """Every observation with the Series it came from.

    Convenience because almost every correlator needs both: the observation
    for its content, and the channel for attribution.
    """
    for one in series:
        for obs in one.observations:
            yield one, obs
