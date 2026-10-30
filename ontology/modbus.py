"""Modbus/TCP ruleset.

Refs are ATT&CK for ICS, not enterprise ATT&CK — the tactics differ enough
that mapping a PLC write to T1071 would mislead a reader.

THE SHAPE OF EVERY RULE HERE. Modbus has no authentication, so nothing about
a message is anomalous by itself: a write is a legal, well-formed, expected
operation. What distinguishes an attack is the SOURCE. So the serious rules
all gate on `rarity` and the command inspector together, and a write from the
established master is reported at LOW or not at all.

This is also why the domain was cheap to add. The questions are the same ones
the engine already answers — is this periodic, is this source new, how many
distinct values — asked of different attributes.
"""

from __future__ import annotations

from core.model import Severity
from core.score import Boost, Condition, Ontology, Rule

__all__ = ["MODBUS"]


MODBUS = Ontology(
    domain="modbus",
    rules=(
        Rule(
            id="modbus.command.unauthorized_write",
            title="Write command from a host with no established history",
            severity=Severity.CRITICAL,
            require=(
                Condition("ics.modbus_command.write", ">=", 0.55),
                # The load-bearing condition. A write from the HMI that
                # writes every day is operations; the same write from a host
                # nothing has seen before is the finding. Without this the
                # rule fires on every legitimate control system.
                #
                # Gated on `novel`, NOT on the blended rarity score. Rarity
                # measured 0.40 for the established master and 0.40 for the
                # rogue — identical, because prevalence drops the initiator
                # and a one-master network is 100% prevalent by definition,
                # while recency's multi-day horizon calls both "recent"
                # inside one capture. `novel` is the only feature that
                # separates 480 prior observations from zero.
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            # Rarity is a GATE here, not a weight. Its blended score is a
            # constant 0.40 on a one-master control network — prevalence is
            # 100% by design and recency's horizon spans days — so including
            # it in the weighting only dragged a real finding below
            # threshold. Novelty is binary and belongs in `require`.
            weigh={"ics.modbus_command.write": 1.0},
            refs=("ics-attack:T0855", "ics-attack:T0836", "cwe:306"),
            supersedes=("modbus.command.write_observed",),
            min_confidence=0.55,
        ),
        Rule(
            id="modbus.command.write_observed",
            title="Write command observed",
            severity=Severity.LOW,
            require=(
                Condition("ics.modbus_command.write", ">=", 0.55),
            ),
            weigh={"ics.modbus_command.write": 1.0},
            # Recorded rather than pressed. On a control network writes are
            # the point; an operator wants them inventoried, not alerted.
            refs=("ics-attack:T0855",),
            min_confidence=0.50,
        ),
        Rule(
            id="modbus.command.device_management",
            title="Diagnostic or device-management command",
            severity=Severity.MEDIUM,
            require=(
                Condition("ics.modbus_command.control", ">=", 0.40),
                Condition("rarity", ">=", 1.0, feature="novel"),
            ),
            weigh={"ics.modbus_command.control": 1.0},
            # Function 8 sub-function 1 restarts communications and
            # sub-function 4 forces listen-only mode. Availability actions,
            # not inspection.
            refs=("ics-attack:T0814", "ics-attack:T0816"),
            min_confidence=0.40,
        ),
        Rule(
            id="modbus.recon.unit_enumeration",
            title="Many unit identifiers addressed from one source",
            severity=Severity.MEDIUM,
            require=(
                Condition("fanout.unit", ">=", 0.30),
                Condition("fanout.unit", ">=", 8.0, feature="unique_values"),
            ),
            weigh={"fanout.unit": 1.0},
            boosts=(
                Boost(
                    when=Condition("ics.modbus_exception", ">=", 10.0,
                                   feature="occurrences"),
                    add=0.15,
                    because="most units answered with an exception, which is "
                            "what walking a range looks like",
                ),
            ),
            refs=("ics-attack:T0846", "ics-attack:T0842"),
            min_confidence=0.45,
        ),
        Rule(
            id="modbus.recon.function_enumeration",
            title="Many function codes tried against one device",
            severity=Severity.MEDIUM,
            require=(
                Condition("fanout.fc", ">=", 0.25),
                Condition("fanout.fc", ">=", 8.0, feature="unique_values"),
            ),
            weigh={"fanout.fc": 1.0},
            boosts=(
                Boost(
                    when=Condition("ics.modbus_exception", ">=", 1.0,
                                   feature="enumeration_shaped"),
                    add=0.15,
                    because="the device answered 'illegal function', so the "
                            "codes were being tried rather than used",
                ),
            ),
            refs=("ics-attack:T0846",),
            min_confidence=0.35,
        ),
        Rule(
            id="modbus.error.exception_volume",
            title="High volume of Modbus exception responses",
            severity=Severity.LOW,
            require=(
                Condition("ics.modbus_exception", ">=", 0.15),
                Condition("ics.modbus_exception", ">=", 20.0,
                          feature="occurrences"),
            ),
            weigh={"ics.modbus_exception": 1.0},
            # LOW on its own: a misconfigured master produces this too. It
            # earns its keep as corroboration for the enumeration rules
            # above.
            refs=("ics-attack:T0846",),
            min_confidence=0.15,
        ),
        Rule(
            id="modbus.timing.response_differential",
            title="Response times split into two clusters",
            severity=Severity.LOW,
            require=(
                Condition("web.timing_differential", ">=", 0.60),
            ),
            weigh={"web.timing_differential": 1.0},
            # Worth recording on a control network because scan-cycle timing
            # is a safety property, but LOW: on Modbus a latency split
            # usually means two different function codes doing different
            # amounts of work, not an oracle.
            refs=("ics-attack:T0814",),
            min_confidence=0.60,
        ),
    ),
)
