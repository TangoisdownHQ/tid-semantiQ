"""MAVLink ruleset.

Same gating as the ICS domains — the message is legal, the SOURCE is the
finding — with one addition that has no ICS equivalent: the telemetry stream
itself can lie, so position integrity is a rule in its own right.

`uav.unsigned_link` is deliberately never required. Unsigned MAVLink is the
default almost everywhere, so requiring it would add nothing, and requiring
its ABSENCE would mean a signed link suppresses command findings — which is
backwards, since signing can be enabled and still misconfigured. It is
recorded as context and referenced only in prose.
"""

from __future__ import annotations

from core.model import Severity
from core.score import Boost, Condition, Ontology, Rule

__all__ = ["MAVLINK"]


MAVLINK = Ontology(
    domain="mavlink",
    rules=(
        Rule(
            id="mavlink.command.disarm_injected",
            title="Disarm command from a system with no established history",
            severity=Severity.CRITICAL,
            require=(
                Condition("uav.mavlink_command.disarm", ">=", 0.80),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"uav.mavlink_command.disarm": 1.0},
            # The most consequential message in the protocol. Disarming an
            # airborne multirotor stops the motors; there is no safe
            # interpretation of one arriving from an unknown system id.
            refs=("ics-attack:T0855", "ics-attack:T0814", "cwe:306"),
            min_confidence=0.80,
        ),
        Rule(
            id="mavlink.command.takeover_injected",
            title="Ground-station binding rewritten from an unknown system",
            severity=Severity.CRITICAL,
            require=(
                Condition("uav.mavlink_command.takeover", ">=", 0.80),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"uav.mavlink_command.takeover": 1.0},
            # SYSID_MYGCS names which ground station the vehicle obeys.
            # Rewriting it is how an injected link promotes itself to
            # operator, and it persists across the rest of the flight.
            refs=("ics-attack:T0855", "ics-attack:T0889", "cwe:306"),
            min_confidence=0.80,
        ),
        Rule(
            id="mavlink.command.actuation_injected",
            title="Flight-affecting command from a system with no established history",
            severity=Severity.CRITICAL,
            require=(
                Condition("uav.mavlink_command.actuate", ">=", 0.65),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"uav.mavlink_command.actuate": 1.0},
            refs=("ics-attack:T0855", "ics-attack:T0831"),
            min_confidence=0.65,
        ),
        Rule(
            id="mavlink.command.mode_change_injected",
            title="Flight mode changed from a system with no established history",
            severity=Severity.HIGH,
            require=(
                Condition("uav.mavlink_command.mode", ">=", 0.55),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"uav.mavlink_command.mode": 1.0},
            refs=("ics-attack:T0855",),
            min_confidence=0.55,
        ),
        Rule(
            id="mavlink.command.parameter_written",
            title="Flight parameter written",
            severity=Severity.MEDIUM,
            require=(
                Condition("uav.mavlink_command.param", ">=", 0.55),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"uav.mavlink_command.param": 1.0},
            refs=("ics-attack:T0836",),
            min_confidence=0.55,
        ),
        Rule(
            id="mavlink.integrity.position_discontinuity",
            title="Reported position moved faster than the airframe could fly",
            severity=Severity.HIGH,
            require=(
                Condition("uav.position_jump", ">=", 0.55),
            ),
            weigh={"uav.position_jump": 1.0},
            boosts=(
                Boost(
                    when=Condition("uav.position_jump", ">=", 2.0,
                                   feature="over_limit"),
                    add=0.10,
                    because="the implied speed exceeds twice any plausible "
                            "airframe, so a fast vehicle cannot explain it",
                ),
            ),
            # HIGH rather than CRITICAL: a capture gap or a reacquired fix
            # produces the same discontinuity, and the finding says so. The
            # confirmation is the vehicle's own reported ground speed, which
            # an injected position usually fails to match.
            refs=("ics-attack:T0830", "ics-attack:T0856", "cwe:345"),
            min_confidence=0.55,
        ),
    ),
)
