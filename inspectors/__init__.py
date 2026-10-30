"""Inspectors, grouped into per-domain stacks.

Mirrors `core/primitives/__init__.py`: a domain selects from a shared set
rather than inventing its own. Unlike primitives, inspectors ARE
domain-specific by nature — a cookie flag means nothing on a CAN bus — so the
shared asset here is the interface and the redaction path, not the logic.
"""

from __future__ import annotations

from typing import Dict, Sequence

from core.inspect import Inspector
from inspectors.auth import CookieSecurity, JwtWeakness, TokenInUrl
from inspectors.ics import (
    Dnp3Command,
    Dnp3Indications,
    ModbusCommand,
    ModbusException,
)
from inspectors.uav import (
    MavlinkCommand,
    MavlinkPositionJump,
    MavlinkUnsigned,
)
from inspectors.web import CorsPolicy, DisclosureHeaders, OAuthFlow, SecretsInResponse

__all__ = ["INSPECTOR_STACKS", "inspectors_for"]


INSPECTOR_STACKS: Dict[str, Sequence[Inspector]] = {
    "http": (
        JwtWeakness(),
        CookieSecurity(),
        TokenInUrl(),
        CorsPolicy(),
        SecretsInResponse(),
        OAuthFlow(),
        DisclosureHeaders(),
    ),
    # Modbus needs only two, and both are classifiers rather than judges —
    # the protocol has no authentication, so nothing about a message is
    # anomalous by itself. The rules combine these with `rarity` to ask
    # whether the SOURCE is expected.
    "modbus": (
        ModbusCommand(),
        ModbusException(),
    ),
    # DNP3 grades its commands more finely than Modbus, and adds the
    # outstation's own Internal Indications — the device reporting on itself,
    # which evidences an effect rather than a command.
    "dnp3": (
        Dnp3Command(),
        Dnp3Indications(),
    ),
    # MAVLink adds a kind of question the ICS domains do not have: a control
    # network's state lives in the device, but a vehicle's state arrives in a
    # telemetry stream that can itself be lying.
    "mavlink": (
        MavlinkCommand(),
        MavlinkPositionJump(),
        MavlinkUnsigned(),
    ),
}


def inspectors_for(domain: str) -> Sequence[Inspector]:
    """Inspectors for a domain. Empty for behavioural-only domains, where
    there are no messages to inspect."""
    return INSPECTOR_STACKS.get(domain, ())
