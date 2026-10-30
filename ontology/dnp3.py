"""DNP3 (IEEE 1815) ruleset.

Same shape as the Modbus rules — gate on the SOURCE, not on the message,
because DNP3 over TCP has no authentication either. What differs is that DNP3
distinguishes several kinds of consequence, and they are not degrees of the
same thing:

    operate     closes a breaker or moves a setpoint — physical effect
    restart     the device stops
    suppress    the device stops REPORTING; the plant is untouched but the
                operator goes blind
    select      arms a point; half of a select-operate pair

`suppress` gets its own CRITICAL rule rather than being folded into the
others. DISABLE_UNSOLICITED is not an attack on the process, it is an attack
on the operator's view of the process — and an attacker who wants a change to
go unnoticed sends it first. Treating it as a lesser "configuration" event
would miss the one message that makes the rest invisible.
"""

from __future__ import annotations

from core.model import Severity
from core.score import Boost, Condition, Ontology, Rule

__all__ = ["DNP3"]


DNP3 = Ontology(
    domain="dnp3",
    rules=(
        Rule(
            id="dnp3.command.unauthorized_control",
            title="Control command from a host with no established history",
            severity=Severity.CRITICAL,
            require=(
                Condition("ics.dnp3_command.operate", ">=", 0.65),
                # Novelty, not the blended rarity score — see the long note
                # in ontology/modbus.py. On a SCADA network with one master,
                # prevalence is 100% by construction and cannot see a second
                # one.
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"ics.dnp3_command.operate": 1.0},
            refs=("ics-attack:T0855", "ics-attack:T0831", "cwe:306"),
            supersedes=("dnp3.command.control_observed",),
            min_confidence=0.65,
        ),
        Rule(
            id="dnp3.command.unauthorized_restart",
            title="Device restart or stop from a host with no established history",
            severity=Severity.CRITICAL,
            require=(
                Condition("ics.dnp3_command.restart", ">=", 0.65),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"ics.dnp3_command.restart": 1.0},
            boosts=(
                Boost(
                    when=Condition("ics.dnp3_indications", ">=", 1.0,
                                   feature="restarted"),
                    add=0.20,
                    because="the outstation then reported the Device Restart "
                            "indication, so the command took effect",
                ),
            ),
            refs=("ics-attack:T0814", "ics-attack:T0816", "ics-attack:T0878"),
            min_confidence=0.65,
        ),
        Rule(
            id="dnp3.command.unsolicited_disabled",
            title="Unsolicited reporting disabled — the master is being blinded",
            severity=Severity.CRITICAL,
            require=(
                Condition("ics.dnp3_command.suppress", ">=", 0.60),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"ics.dnp3_command.suppress": 1.0},
            # Its own rule because the consequence is different in kind. The
            # process is untouched; what stops is the operator's visibility,
            # which is why it tends to arrive before anything else.
            refs=("ics-attack:T0878", "ics-attack:T0814", "ics-attack:T0815"),
            min_confidence=0.60,
        ),
        Rule(
            id="dnp3.command.control_observed",
            title="Control command observed",
            severity=Severity.LOW,
            require=(
                Condition("ics.dnp3_command.operate", ">=", 0.60),
            ),
            weigh={"ics.dnp3_command.operate": 1.0},
            # Inventory, not an alert. Operating a control point is what a
            # SCADA master is for.
            refs=("ics-attack:T0855",),
            min_confidence=0.55,
        ),
        Rule(
            id="dnp3.device.restart_reported",
            title="Outstation reported a restart",
            severity=Severity.MEDIUM,
            require=(
                Condition("ics.dnp3_indications", ">=", 0.60),
                Condition("ics.dnp3_indications", ">=", 1.0, feature="restarted"),
            ),
            weigh={"ics.dnp3_indications": 1.0},
            # Evidence of the EFFECT, independent of whether the command was
            # captured. Survives a partial capture that missed the request.
            refs=("ics-attack:T0816",),
            min_confidence=0.60,
        ),
        Rule(
            id="dnp3.recon.address_enumeration",
            title="Many DNP3 link addresses probed from one source",
            severity=Severity.MEDIUM,
            require=(
                Condition("fanout.link_dst", ">=", 0.30),
                Condition("fanout.link_dst", ">=", 6.0, feature="unique_values"),
            ),
            weigh={"fanout.link_dst": 1.0},
            boosts=(
                Boost(
                    when=Condition("ics.dnp3_indications", ">=", 0.20),
                    add=0.10,
                    because="outstations answered with error indications, "
                            "which is what probing addresses looks like",
                ),
            ),
            refs=("ics-attack:T0846",),
            min_confidence=0.45,
        ),
        Rule(
            id="dnp3.recon.function_enumeration",
            title="Many DNP3 function codes tried against one outstation",
            severity=Severity.MEDIUM,
            require=(
                Condition("fanout.fc", ">=", 0.25),
                Condition("fanout.fc", ">=", 6.0, feature="unique_values"),
            ),
            weigh={"fanout.fc": 1.0},
            refs=("ics-attack:T0846",),
            min_confidence=0.35,
        ),
    ),
)
