"""Output sinks and report rendering."""

from __future__ import annotations

from typing import List, Sequence

from core.model import Evidence

__all__ = ["collect_advisories"]


def collect_advisories(evidences: Sequence[Evidence]) -> List[str]:
    """Zero-scored evidence that explains what an analysis would need.

    Deliberately separate from findings. A correlator that cannot assess
    something must not score it — "we could not measure this" is not
    "this is weak" — but the operator still needs to know an analysis was
    skipped and what would unblock it.
    """
    out: List[str] = []
    for evidence in evidences:
        for inspection in evidence.inspections:
            reason = inspection.facts.get("insufficient")
            if not reason or inspection.score > 0.0:
                continue
            host = evidence.channel.dims.get("host", evidence.channel.domain)
            name = inspection.facts.get("token.name", inspection.name)
            line = f"{host} [{name}]: {reason}"
            if line not in out:
                out.append(line)
    return out
