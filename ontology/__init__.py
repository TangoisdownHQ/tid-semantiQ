"""Rulesets, one per domain.

Onboarding a domain adds a module here and a primitive stack in
`core/primitives/__init__.py`. If it also needs a change to `core/score.py`,
the primitive set was wrong — that is the designed failure signal.
"""

from __future__ import annotations

from typing import Dict

from core.score import Ontology
from ontology.dnp3 import DNP3
from ontology.dns import DNS
from ontology.http import HTTP
from ontology.mavlink import MAVLINK
from ontology.modbus import MODBUS
from ontology.net import NET

__all__ = ["ONTOLOGIES", "for_domain"]

ONTOLOGIES: Dict[str, Ontology] = {
    NET.domain: NET,
    DNS.domain: DNS,
    HTTP.domain: HTTP,
    MODBUS.domain: MODBUS,
    DNP3.domain: DNP3,
    # MAVLink is the one domain here with a NATIVE parser rather than a
    # tshark profile: Wireshark ships no MAVLink dissector (the one that
    # exists is a Lua plugin generated from the MAVLink XML). See
    # capture/mavlink.py.
    MAVLINK.domain: MAVLINK,
    # v0.5  can, ble
}


def for_domain(domain: str) -> Ontology:
    return ONTOLOGIES[domain]
