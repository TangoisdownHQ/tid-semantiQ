"""Cross-host credential and identifier leakage.

The highest-value finding this tool can produce, and the one a proxy-oriented
workflow routinely misses — because the defect is not in any single request.
Request A is a normal authenticated call. Request B is a normal analytics
beacon. The bug is that both carry the same bearer token, and you only see it
holding the whole capture at once.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Set, Tuple
from urllib.parse import parse_qsl

from core.correlate import Correlator, CorrelationOutput, observations_of
from core.suffixes import party
from core.model import Channel, Context, InspectionResult, Locus, Series

__all__ = ["CredentialReuse", "IdentifierSpray"]


def _host_of(channel: Channel) -> str:
    return channel.dims.get("host") or (
        channel.responder.value if channel.responder else "?"
    )


def _registrable(host: str) -> str:
    """Registrable domain via the Public Suffix List — see core/suffixes.py.

    Replaces a label-count approximation that answered `co.uk` for every UK
    organisation, so a credential shared between two unrelated companies read
    as first-party plumbing and was suppressed. It was also wrong for cloud
    suffixes in the other direction: two S3 buckets both answered
    `amazonaws.com` and so looked like the same party.
    """
    return party(host)


def _primary_domain(series: Sequence[Series]) -> str:
    """The registrable domain the client talks to most, by request count.

    Used to decide which side of a credential-sharing pair is the third
    party. Request volume is the proxy because it is what a human reads off
    a capture: the app's own API dominates, the analytics vendor does not.
    Ties break alphabetically so the output is deterministic.
    """
    counts: Dict[str, int] = defaultdict(int)
    for one in series:
        domain = _registrable(_host_of(one.channel))
        counts[domain] += sum(
            1 for obs in one.observations if obs.kind == "http_request"
        )
    if not counts:
        return ""
    best = max(counts.values())
    return sorted(d for d, c in counts.items() if c == best)[0]


class CredentialReuse(Correlator):
    """One credential observed going to more than one host.

    SEVERITY DEPENDS ON THE PAIR, not on the token. A token sent to
    `api.example.com` and `cdn.example.com` is first-party sharing — worth
    noting, rarely a bug. The same token sent to an unrelated registrable
    domain is a credential disclosed to a third party, which is a reportable
    finding and sometimes a serious one.

    So the score keys on whether the registrable domains differ, and the
    finding is attributed to the RECEIVING channel — the host that should not
    have the credential, and the request a triager opens first.

    Credentials are matched by exact value, deliberately. Fuzzy matching
    across near-identical tokens would invent relationships, and "the same
    bytes arrived at two hosts" is a claim that needs no inference.
    """

    name = "auth.credential_reuse"
    domains = ("http",)

    _BEARER = re.compile(r"(?:bearer|token)\s+(\S+)", re.I)
    _JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.?[A-Za-z0-9_-]*")
    #: Minimum length for a string to be treated as a credential. Short
    #: values collide across unrelated requests and would manufacture
    #: "reuse" out of a shared `token=1` debug flag.
    MIN_LENGTH = 20

    def correlate(
        self, series: Sequence[Series], ctx: Context
    ) -> Iterable[CorrelationOutput]:
        relevant = self.relevant(series)
        primary = _primary_domain(relevant)

        # credential value -> host -> (channel, loci, where it was found)
        sightings: Dict[str, Dict[str, Tuple[Channel, List[Locus], Set[str]]]] = (
            defaultdict(dict)
        )

        for one, obs in observations_of(relevant):
            if obs.kind != "http_request":
                continue
            host = _host_of(one.channel)
            for location, credential in self._credentials(obs):
                if len(credential) < self.MIN_LENGTH:
                    continue
                entry = sightings[credential].get(host)
                if entry is None:
                    sightings[credential][host] = (
                        one.channel,
                        [obs.locus] if obs.locus else [],
                        {location},
                    )
                else:
                    if obs.locus and obs.locus not in entry[1]:
                        entry[1].append(obs.locus)
                    entry[2].add(location)

        for credential, by_host in sightings.items():
            if len(by_host) < 2:
                continue

            hosts = sorted(by_host)
            domains = {_registrable(h) for h in hosts}
            first_party = len(domains) == 1

            # Which host should not have this? The one outside the capture's
            # PRIMARY domain — the domain the client predominantly talks to.
            #
            # Counting hosts that merely share this credential does not work:
            # with one first-party host and one third party there are two
            # domains of one host each, no majority, and the tie-break lands
            # arbitrarily — in testing it blamed the legitimate API for
            # leaking to the analytics host, exactly backwards. Request
            # volume across the whole capture is a far better proxy for
            # "first party", and is what a human would use.
            outsiders = [h for h in hosts if _registrable(h) != primary]

            targets = outsiders or hosts[1:]
            for host in targets:
                channel, loci, locations = by_host[host]
                score = 0.45 if first_party else 0.90
                notes = [
                    f"also sent to: {', '.join(h for h in hosts if h != host)}",
                    "matched on exact credential bytes, not inference",
                ]
                if first_party:
                    notes.append(
                        "same registrable domain — likely first-party sharing"
                    )
                else:
                    notes.append(
                        "registrable domains differ, per the Public Suffix "
                        "List — including its private section, so two S3 "
                        "buckets or two GitHub Pages sites count as separate "
                        "parties"
                    )
                if "query" in locations:
                    score = min(1.0, score + 0.05)
                    notes.append("carried in a query string at this host")

                yield channel, InspectionResult(
                    name=self.name,
                    score=score,
                    facts={
                        "received_by": host,
                        "also_sent_to": ", ".join(h for h in hosts if h != host),
                        "host_count": str(len(hosts)),
                        "domain_split": "same" if first_party else "different",
                        "carried_in": ", ".join(sorted(locations)),
                        "credential": credential,     # masked on output
                    },
                    secret_facts=("credential",),
                    features={
                        "hosts": float(len(hosts)),
                        "registrable_domains": float(len(domains)),
                        "cross_party": 0.0 if first_party else 1.0,
                    },
                    occurrences=len(loci) or 1,
                    loci=tuple(loci[:8]),
                    notes=tuple(notes),
                )

    def _credentials(self, obs) -> List[Tuple[str, str]]:
        """Credential-shaped strings, with where each was found."""
        found: List[Tuple[str, str]] = []

        auth = str(obs.attrs.get("authorization", ""))
        for match in self._BEARER.finditer(auth):
            found.append(("authorization", match.group(1)))

        cookie = str(obs.attrs.get("cookie", ""))
        for _, value in parse_qsl(cookie.replace("; ", "&"), keep_blank_values=True):
            if value:
                found.append(("cookie", value))

        query = str(obs.attrs.get("query", ""))
        for key, value in parse_qsl(query, keep_blank_values=True):
            if not value:
                continue
            # In a query string, only take values that actually look like a
            # credential — otherwise every shared `limit=20` reads as reuse.
            if self._JWT.match(value) or _credential_name(key):
                found.append(("query", value))

        return found


def _credential_name(key: str) -> bool:
    lowered = key.lower()
    return any(
        hint in lowered
        for hint in ("token", "auth", "key", "secret", "session", "sid",
                     "password", "signature", "jwt", "code", "credential")
    )


class IdentifierSpray(Correlator):
    """A user identifier sent to several hosts.

    Weaker than credential reuse and reported more quietly: a user id or
    email reaching an analytics host is often disclosed by design, sometimes
    a privacy finding, and occasionally the thing a client's compliance team
    actually cares about. It is reported as evidence of a data flow, not as a
    vulnerability, and the severity reflects that.
    """

    name = "privacy.identifier_spray"
    domains = ("http",)

    _EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

    def correlate(
        self, series: Sequence[Series], ctx: Context
    ) -> Iterable[CorrelationOutput]:
        relevant = self.relevant(series)
        primary = _primary_domain(relevant)
        sightings: Dict[str, Dict[str, Tuple[Channel, List[Locus]]]] = defaultdict(dict)

        for one, obs in observations_of(relevant):
            if obs.kind != "http_request":
                continue
            host = _host_of(one.channel)
            for identifier in self._identifiers(obs):
                entry = sightings[identifier].get(host)
                if entry is None:
                    sightings[identifier][host] = (
                        one.channel, [obs.locus] if obs.locus else []
                    )
                elif obs.locus and obs.locus not in entry[1]:
                    entry[1].append(obs.locus)

        for identifier, by_host in sightings.items():
            domains = {_registrable(h) for h in by_host}
            if len(domains) < 2:
                continue
            hosts = sorted(by_host)

            for host in [h for h in hosts if _registrable(h) != primary]:
                channel, loci = by_host[host]
                yield channel, InspectionResult(
                    name=self.name,
                    score=0.55,
                    facts={
                        "received_by": host,
                        "identifier_kind": (
                            "email" if "@" in identifier else "user id"
                        ),
                        "also_sent_to": ", ".join(h for h in hosts if h != host),
                        "identifier": identifier,      # masked on output
                    },
                    secret_facts=("identifier",),
                    features={"hosts": float(len(hosts))},
                    occurrences=len(loci) or 1,
                    loci=tuple(loci[:8]),
                    notes=(
                        "a data flow, not necessarily a vulnerability — "
                        "check whether this processor is disclosed",
                    ),
                )

    def _identifiers(self, obs) -> Set[str]:
        found: Set[str] = set()
        query = str(obs.attrs.get("query", ""))
        for key, value in parse_qsl(query, keep_blank_values=True):
            if not value:
                continue
            if self._EMAIL.fullmatch(value):
                found.add(value)
            elif key.lower() in ("uid", "user_id", "userid", "user", "sub",
                                 "account_id", "customer_id") and len(value) >= 4:
                found.add(value)
        return found
