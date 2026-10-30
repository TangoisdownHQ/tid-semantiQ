"""DNS ruleset.

DNS earns its own ontology because the interesting cardinality is over query
names beneath a parent zone, which needs its own `dims` — see §5 of the spec
on why `Fanout` works the way it does.

Worth building second, ahead of anything exotic: the signals are cheap, the
math is the same, and tunnelling has a far better evidence-to-noise ratio
than TLS metadata inference because the covert channel has to encode data
into names that a legitimate resolver would never emit.
"""

from __future__ import annotations

from core.model import Severity
from core.score import Boost, Condition, Ontology, Rule

__all__ = ["DNS"]


DNS = Ontology(
    domain="dns",
    rules=(
        Rule(
            id="dns.tunnel.high_cardinality_zone",
            title="High-cardinality unique subdomains under one zone",
            severity=Severity.HIGH,
            require=(
                # Nearly every query a distinct name is the tunnelling
                # signature: a cache-respecting client reuses names, an
                # encoder cannot.
                Condition("fanout.qname", ">=", 0.60),
                Condition("fanout.qname", ">=", 0.90, feature="unique_fraction"),
                Condition("fanout.qname", ">=", 50.0, feature="unique_values"),
            ),
            weigh={"fanout.qname": 0.65, "rarity": 0.35},
            boosts=(
                Boost(
                    when=Condition("entropy", ">=", 0.75),
                    add=0.10,
                    because="query names are near-random, consistent with encoded payload",
                ),
            ),
            refs=("attack:T1071.004", "attack:T1048.003"),
            min_confidence=0.60,
        ),
        Rule(
            id="dns.beacon.periodic_lookup",
            title="Periodic lookup of an uncommon name",
            severity=Severity.MEDIUM,
            require=(
                Condition("periodicity", ">=", 0.70),
                Condition("rarity", ">=", 0.60),
            ),
            weigh={"periodicity": 0.45, "rarity": 0.45, "burstiness": 0.10},
            refs=("attack:T1071.004",),
            min_confidence=0.60,
        ),
        # The two rules below were added because a real capture needed them.
        # Twenty minutes of ordinary browsing contained 11,859 NXDOMAIN
        # against 1,338 NOERROR, and the ontology had nothing to say about
        # it — the tool could watch 90% of a network's name resolution fail
        # and report no observation of any kind.
        Rule(
            id="dns.resolution.mostly_failing_zone",
            title="Most lookups under this zone do not resolve",
            severity=Severity.INFO,
            require=(
                # Single-condition on purpose, and the only rule in the tool
                # that is. This states a measurement, not an inference: if
                # the failure rate is high then lookups are failing, full
                # stop. There is nothing to corroborate because nothing is
                # being guessed at. The honest-sounding alternative — gate
                # it behind rarity so it looks like the other rules — would
                # suppress exactly the benign-but-worth-knowing case (a
                # mistyped search suffix, decommissioned infrastructure)
                # that makes this worth reporting to an operator at all.
                Condition("failure_rate.rcode", ">=", 0.65),
            ),
            weigh={"failure_rate.rcode": 1.0},
            refs=(),
            min_confidence=0.50,
        ),
        Rule(
            id="dns.dga.failing_random_names",
            title="Many distinct, near-random names, nearly all failing to resolve",
            severity=Severity.HIGH,
            require=(
                # This one IS an inference — "algorithmically generated" is a
                # claim about an absent generator — so it carries the full
                # conjunction. A DGA hunting for a live rendezvous point
                # leaves all three marks at once: many names, high entropy
                # in them, and overwhelmingly NXDOMAIN because only one of
                # the candidates was ever registered.
                Condition("failure_rate.rcode", ">=", 0.80),
                Condition("fanout.qname", ">=", 0.60),
                Condition("fanout.qname", ">=", 0.90, feature="unique_fraction"),
                Condition("entropy", ">=", 0.70),
            ),
            weigh={
                "failure_rate.rcode": 0.40,
                "fanout.qname": 0.35,
                "entropy": 0.25,
            },
            # A high-cardinality zone whose names mostly RESOLVE is
            # tunnelling; one whose names mostly FAIL is a DGA searching.
            # Both fire on cardinality, so without this the operator gets
            # two findings describing one behaviour and has to work out
            # which reading applies.
            supersedes=("dns.tunnel.high_cardinality_zone",),
            refs=("attack:T1568.002", "attack:T1071.004"),
            min_confidence=0.65,
        ),
    ),
)
