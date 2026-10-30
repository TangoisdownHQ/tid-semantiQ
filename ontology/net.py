"""Network ruleset — TCP/TLS behaviour.

Every rule here is written against the finding that drove the whole design:
an exact cron poller scores 1.000 on periodicity, identical to a zero-jitter
beacon (docs/SPEC-observation.md §6). Periodicity alone is therefore never
allowed to produce a finding. The beacon rule REQUIRES rarity, and that
requirement is the difference between a usable detector and an alert feed
full of update checkers.
"""

from __future__ import annotations

from core.model import Severity
from core.score import Boost, Condition, Ontology, Rule

__all__ = ["NET"]


NET = Ontology(
    domain="net",
    rules=(
        Rule(
            id="net.beacon.periodic_callback",
            title="Periodic outbound callback to an uncommon destination",
            severity=Severity.HIGH,
            require=(
                Condition("periodicity", ">=", 0.65),
                # The load-bearing requirement. Without it this rule fires on
                # every package manager, telemetry agent and keepalive on the
                # network. Rarity is not corroboration here, it is the gate.
                Condition("rarity", ">=", 0.50),
            ),
            weigh={
                "periodicity": 0.45,
                "rarity": 0.40,
                # Jitter is weighted LOW and deliberately so. The hypothesis
                # that malware jitters while legitimate timers fire exactly is
                # plausible and unproven (see Jitter's docstring); it earns a
                # small weight until lab data settles it, not a large one.
                "jitter": 0.15,
            },
            boosts=(
                Boost(
                    when=Condition("asymmetry", ">=", 0.40),
                    add=0.05,
                    because="volume is strongly outbound for a callback channel",
                ),
            ),
            refs=("attack:T1071.001", "attack:T1573"),
            min_confidence=0.60,
        ),
        Rule(
            id="net.beacon.low_and_slow",
            title="Low-volume long-interval callback",
            severity=Severity.MEDIUM,
            require=(
                Condition("periodicity", ">=", 0.55),
                Condition("rarity", ">=", 0.60),
                # Long dwell between callbacks: the shape chosen to stay under
                # volumetric and session-count thresholds.
                Condition("periodicity", ">=", 300.0, feature="period_s"),
            ),
            weigh={"periodicity": 0.40, "rarity": 0.50, "burstiness": 0.10},
            refs=("attack:T1071.001", "attack:T1029"),
            min_confidence=0.60,
        ),
        Rule(
            id="net.exfil.asymmetric_transfer",
            title="Sustained outbound-dominant transfer",
            severity=Severity.HIGH,
            require=(
                Condition("asymmetry", ">=", 0.50),
                Condition("asymmetry", ">=", 0.70, feature="asymmetry"),
                Condition("rarity", ">=", 0.40),
            ),
            weigh={"asymmetry": 0.60, "rarity": 0.40},
            boosts=(
                Boost(
                    when=Condition("burstiness", ">=", 0.60),
                    add=0.05,
                    because="transfer is clustered rather than steady, consistent with staged egress",
                ),
            ),
            refs=("attack:T1041", "attack:T1030"),
            min_confidence=0.60,
        ),
        Rule(
            id="net.recon.port_sweep",
            title="Many distinct destination ports from one source",
            severity=Severity.MEDIUM,
            require=(
                Condition("fanout.dport", ">=", 0.50),
                Condition("fanout.dport", ">=", 20.0, feature="unique_values"),
                Condition("fanout.dport", ">=", 0.80, feature="unique_fraction"),
            ),
            weigh={"fanout.dport": 0.80, "burstiness": 0.20},
            refs=("attack:T1046",),
            min_confidence=0.55,
        ),
    ),
)
