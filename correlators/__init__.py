"""Correlators, grouped by domain.

Third and last analyzer scope — relationships BETWEEN channels. See
`core/correlate.py` for why one Series and one Observation were not enough.
"""

from __future__ import annotations

from typing import Dict, Sequence

from core.correlate import Correlator
from correlators.credentials import CredentialReuse, IdentifierSpray
from correlators.oauth import RefreshTokenRotation
from correlators.sessions import SessionFixation
from correlators.tokens import SessionTokenQuality

__all__ = ["CORRELATORS", "correlators_for"]


#: Keyed by domain for symmetry with the other two registries, but a
#: correlator sees every Series regardless — the key says which domain's
#: presence makes it worth running, not what it is allowed to read.
CORRELATORS: Dict[str, Sequence[Correlator]] = {
    "http": (
        CredentialReuse(),
        IdentifierSpray(),
        SessionTokenQuality(),
        SessionFixation(),
        RefreshTokenRotation(),
    ),
}


def correlators_for(domains: Sequence[str]) -> Sequence[Correlator]:
    """Every correlator relevant to the domains present in this capture."""
    seen, out = set(), []
    for domain in domains:
        for correlator in CORRELATORS.get(domain, ()):
            if correlator.name not in seen:
                seen.add(correlator.name)
                out.append(correlator)
    return tuple(out)
