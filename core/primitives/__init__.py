"""The primitive library, and the per-domain stacks that select them.

A domain does not get to invent primitives. It gets to choose which of them
to run, how to configure them, and — in `ontology/` — what combinations
of their outputs mean. That constraint is what keeps domain #4 cheap: adding
Modbus is a parser plus a dims choice plus a primitive selection, not new
mathematics.
"""

from __future__ import annotations

from typing import Dict, Sequence

from core.model import Direction
from core.primitives.base import Primitive
from core.primitives.structure import (
    Asymmetry,
    Entropy,
    FailureRate,
    Fanout,
    Rarity,
    SequenceOrder,
)
from core.primitives.latency import ResponseTimeDifferential
from core.primitives.timing import Burstiness, Jitter, Periodicity

__all__ = [
    "Primitive",
    "Periodicity",
    "Jitter",
    "Burstiness",
    "Asymmetry",
    "Fanout",
    "ResponseTimeDifferential",
    "Rarity",
    "Entropy",
    "SequenceOrder",
    "FailureRate",
    "STACKS",
    "stack_for",
]


# --------------------------------------------------------------------------
# domain stacks
# --------------------------------------------------------------------------
#
# Note how little varies between them. The network stack measures egress
# timing because a beacon's cadence is set by the client; the CAN stack
# measures all directions because the bus is broadcast. Everything else is
# the same eight functions.

STACKS: Dict[str, Sequence[Primitive]] = {
    # v0.1 — TCP/TLS/HTTP. The hardest domain, because general-purpose
    # traffic is the noisiest. Prove the primitives here first.
    "net": (
        Periodicity(direction=Direction.EGRESS),
        Jitter(direction=Direction.EGRESS),
        Burstiness(),
        Asymmetry(),
        Rarity(),
        Fanout(attr="dport"),
    ),
    # DNS is split from net because the interesting cardinality is over
    # query names under a parent zone, which requires its own dims.
    "dns": (
        Periodicity(direction=Direction.EGRESS),
        Burstiness(),
        Fanout(attr="qname"),
        Rarity(),
        Entropy(),
        # One success value rather than six failures: the rcode registry has
        # room to grow, and an rcode this build does not recognise is
        # certainly not a resolution that worked.
        FailureRate(
            attr="rcode_name",
            success_values=frozenset({"NOERROR"}),
            label="failure_rate.rcode",
        ),
    ),
    # v0.2 — bug-bounty mode. Same capture, cleartext payloads via
    # operator-supplied keys, different ontology.
    "http": (
        # Fanout(attr="path") was here and no rule ever referenced it —
        # computed on every run and discarded. Path cardinality is answered
        # properly by out/inventory.py, which templates identifier segments
        # and reports what each placeholder replaced.
        Asymmetry(),
        Entropy(),
        Rarity(),
        ResponseTimeDifferential(),
    ),
    # Modbus/TCP. No new mathematics: the same eight primitives, pointed at
    # different attribute names. Highly periodic by design — a master polls
    # on a fixed scan cycle — which is where the timing primitives are
    # strongest.
    "modbus": (
        # EGRESS only: the cadence belongs to the master's scan cycle, and
        # responses arrive on the PLC's schedule rather than the master's.
        #
        # GROUPED BY FUNCTION CODE, and that is not optional. A master
        # polling two function codes 50ms apart on a 1s cycle yields
        # intervals of 0.05, 0.95, 0.05, 0.95; measured whole that scored
        # 0.001 while a flat-rate scanner scored 1.000 — backwards. Each
        # function code is its own cadence.
        Periodicity(direction=Direction.EGRESS, group_attr="fc"),
        Jitter(direction=Direction.EGRESS),
        Burstiness(),
        Rarity(),
        # Unit id and function code live in `attrs`, not `dims`, precisely so
        # these can count them — enumeration is the scanning signature.
        # Requests only: responses echo the unit id, which halved the
        # apparent concentration of a sweep. Saturations are domain-sized —
        # a network with three units does not address twelve by accident.
        Fanout(attr="unit", kind="modbus_request", saturation=12),
        Fanout(attr="fc", kind="modbus_request", saturation=8),
        # Wireshark supplies `modbus.response_time`, so the HTTP latency
        # analyzer works here unchanged. This is what parameterising it by
        # attribute name bought.
        ResponseTimeDifferential(
            group_attr="fc", elapsed_attr="elapsed_s", label_attr="exception",
        ),
        # SequenceOrder is deliberately ABSENT until a validated grammar
        # exists. It shipped here as `allowed=frozenset()`, which permits
        # nothing and therefore scores every transition as a violation —
        # inert only because no rule referenced it. See its `applies_to`.
    ),
    # DNP3. Same eight primitives again. No ResponseTimeDifferential: unlike
    # Modbus, Wireshark exposes no DNP3 response-time field, so there is no
    # elapsed measurement to cluster — the primitive would decline anyway,
    # and leaving it out says so explicitly.
    "dnp3": (
        Periodicity(direction=Direction.EGRESS, group_attr="fc"),
        Jitter(direction=Direction.EGRESS),
        Burstiness(),
        Rarity(),
        # Function codes and DNP3 link addresses are in `attrs`, so these can
        # count them. An address sweep is how an attacker finds outstations
        # behind a single IP.
        Fanout(attr="fc", kind="dnp3_request", saturation=8),
        Fanout(attr="link_dst", kind="dnp3_request", saturation=8),
    ),
    # MAVLink. A NATIVE parser rather than a tshark profile — Wireshark
    # ships no MAVLink dissector — which is why this domain demonstrates the
    # other half of the capture contract. The primitives are unchanged
    # regardless.
    "mavlink": (
        # Grouped by message id for the reason Modbus needed it: a stream
        # interleaving 1 Hz heartbeats with 5 Hz position reports is bimodal
        # when measured whole, and each message type has its own cadence.
        Periodicity(group_attr="msgid"),
        Burstiness(),
        Rarity(),
        Fanout(attr="msgid", saturation=20),
    ),
    # v0.5 — cheap hardware, broadcast domains: no initiator/responder pair,
    # so asymmetry declines to answer and timing carries the weight.
    "can": (
        Periodicity(),
        Jitter(),
        Burstiness(),
        Rarity(),
    ),
    "ble": (
        Periodicity(),
        Burstiness(),
        Rarity(),
        Fanout(attr="adv_payload"),
    ),
}


def stack_for(domain: str) -> Sequence[Primitive]:
    """Primitives to run for a domain. Unknown domains get the timing core,
    which is always applicable and never domain-specific."""
    return STACKS.get(domain, (Periodicity(), Burstiness(), Rarity()))
