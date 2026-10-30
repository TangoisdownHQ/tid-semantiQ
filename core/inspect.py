"""The inspector interface — per-message content analysis.

Sibling of `Primitive`, and the reason both exist:

    Primitive   Series      -> statistics      "how does this channel behave?"
    Inspector   Observation -> facts           "what is wrong with this message?"

Bug-bounty findings are overwhelmingly the second shape. A cookie missing
`Secure`, a JWT with `alg: none`, a bearer token in a query string — none of
those are statistics, and pushing them through `Primitive` would have meant
pretending they were. Keeping them a separate type costs one interface and
preserves both invariants: inspections land in the same `Evidence`, the
scorer still computes every confidence, and `Finding` is still frozen.

FOLDING IS NOT OPTIONAL. An inspector runs per message. A cookie missing
`Secure` is set on every response from an endpoint, so a 2000-request capture
yields 2000 identical inspections. `fold()` collapses them per name — worst
score wins, repeats are counted, and a bounded sample of loci is kept. Without
it the report is unreadable and the finding count is meaningless.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from core.model import Context, InspectionResult, Locus, Observation

__all__ = ["Inspector", "fold", "run_inspectors", "MAX_SAMPLE_LOCI"]


#: Loci retained per folded inspection. Enough to show a pattern, few enough
#: to keep a display filter pasteable.
MAX_SAMPLE_LOCI = 8


class Inspector(ABC):
    """One question about the content of a single message.

    Subclasses declare `name` and what they need, then implement `inspect`.
    Same discipline as `Primitive`: no network, no filesystem, no globals,
    deterministic given (Observation, Context), and **return None when the
    question does not apply** rather than a misleading answer.

    Inspectors see UNREDACTED values. They have to — you cannot tell whether
    a JWT is unsigned from a masked string. Masking happens at serialisation
    (`core/redact.py`), so an inspector's duty is simply to put secrets in
    `facts` under a key the redactor will recognise, and keep structural
    conclusions in separate keys so they survive.
    """

    #: stable identifier, appears in the ledger and in rule conditions as
    #: "<name>" or "<name>.<feature>" — changing it is a breaking change
    name: str = ""

    #: Observation.attrs keys that must be present for this inspector to run
    requires_attrs: Tuple[str, ...] = ()

    #: True if the inspector needs decrypted payload bytes
    requires_payload: bool = False

    #: Observation.kind values this applies to; empty means any
    kinds: Tuple[str, ...] = ()

    def applies_to(self, obs: Observation, ctx: Context) -> bool:
        if self.kinds and obs.kind not in self.kinds:
            return False
        if self.requires_payload and not obs.payload:
            return False
        for attr in self.requires_attrs:
            if attr not in obs.attrs:
                return False
        return True

    @abstractmethod
    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        """Examine one message. None means "nothing to say about this one"."""
        raise NotImplementedError

    def run(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        if not self.applies_to(obs, ctx):
            return None
        return self.inspect(obs, ctx)

    # -- helper ------------------------------------------------------------

    def _finding(
        self,
        score: float,
        facts: Dict[str, str],
        obs: Observation,
        secret_facts: Tuple[str, ...] = (),
        features: Optional[Dict[str, float]] = None,
        notes: Tuple[str, ...] = (),
    ) -> InspectionResult:
        return InspectionResult(
            name=self.name,
            score=max(0.0, min(1.0, score)),
            facts=facts,
            secret_facts=secret_facts,
            features=features or {},
            occurrences=1,
            loci=(obs.locus,) if obs.locus else (),
            notes=notes,
        )

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"<Inspector {self.name}>"


# --------------------------------------------------------------------------
# folding
# --------------------------------------------------------------------------


def fold(results: Iterable[InspectionResult]) -> Tuple[InspectionResult, ...]:
    """Collapse repeated inspections of the same name into one.

    Keeps the WORST score rather than an average: if one response out of a
    thousand set a cookie without `Secure`, that is the finding, and
    averaging it away would hide it. The count is reported separately so an
    analyst can tell a systemic problem from a one-off.

    Facts are taken from the worst-scoring instance. Merging facts across
    instances would interleave values from different messages into one
    apparent record, which reads as a single coherent finding and is not.
    """
    buckets: Dict[str, List[InspectionResult]] = {}
    for result in results:
        buckets.setdefault(result.name, []).append(result)

    folded: List[InspectionResult] = []
    for name, group in buckets.items():
        worst = max(group, key=lambda r: r.score)
        loci: List[Locus] = []
        for result in group:
            for locus in result.loci:
                if locus not in loci:
                    loci.append(locus)
                if len(loci) >= MAX_SAMPLE_LOCI:
                    break
            if len(loci) >= MAX_SAMPLE_LOCI:
                break

        notes = list(worst.notes)
        total = sum(r.occurrences for r in group)
        if total > 1:
            distinct = len({tuple(sorted(r.facts.items())) for r in group})
            notes.append(
                f"{total} occurrence(s), {distinct} distinct"
                + (f", showing {len(loci)} of {total}" if total > len(loci) else "")
            )

        folded.append(
            InspectionResult(
                name=name,
                score=worst.score,
                facts=worst.facts,
                secret_facts=worst.secret_facts,
                features={**worst.features, "occurrences": float(total)},
                occurrences=total,
                loci=tuple(loci),
                notes=tuple(notes),
            )
        )

    folded.sort(key=lambda r: r.score, reverse=True)
    return tuple(folded)


def run_inspectors(
    observations: Sequence[Observation],
    inspectors: Sequence[Inspector],
    ctx: Context,
) -> Tuple[InspectionResult, ...]:
    """Run every inspector over every message, then fold."""
    raw: List[InspectionResult] = []
    for obs in observations:
        for inspector in inspectors:
            result = inspector.run(obs, ctx)
            if result is not None:
                raw.append(result)
    return fold(raw)
