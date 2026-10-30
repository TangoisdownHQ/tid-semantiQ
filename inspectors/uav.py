"""MAVLink inspectors — command injection and position integrity.

MAVLink has no authentication by default. v2 defines message signing, but it
is off in most deployments, so any host that can reach the link can command
the vehicle. The shape is therefore the same as the ICS protocols: nothing
about a message is anomalous by itself, and the finding is that a system id
nobody has seen is issuing commands.

What differs from ICS is the second half. A control network's state lives in
the device; a vehicle's state is reported in a telemetry stream, and the
stream itself can lie. `MavlinkPositionJump` reads a discontinuity that the
capture layer computed, because a position that moved further than the
airframe could fly means either the capture or the position source is wrong
— and a GPS spoof is the usual reason.
"""

from __future__ import annotations

import math
from typing import Dict, Optional

from core.inspect import Inspector
from core.model import Context, InspectionResult, Observation

__all__ = ["MavlinkCommand", "MavlinkPositionJump", "MavlinkUnsigned"]


class MavlinkCommand(Inspector):
    """A MAVLink message that changes vehicle state.

    Emits a CATEGORY-SCOPED name, for the reason the ICS inspectors do: a
    hijack capture carries a mode change AND a disarm AND a parameter write,
    and folding them under one name would keep only the highest-scoring one
    and silently disable every rule gating on the others.

    Disarm is graded above arm. Arming a vehicle on the ground is routine;
    disarming one that reports itself airborne stops the motors.
    """

    name = "uav.mavlink_command"
    kinds = ("mavlink_message",)
    requires_attrs = ("msgid",)

    #: msgid -> (category, score, effect)
    _COMMANDS = {
        "76": ("command", 0.65, "sends a MAV_CMD to the vehicle"),
        "11": ("mode", 0.60, "changes flight mode"),
        "23": ("param", 0.60, "writes a flight parameter"),
    }

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        entry = self._COMMANDS.get(str(obs.attrs.get("msgid", "")))
        if entry is None:
            return None
        category, score, effect = entry

        facts: Dict[str, str] = {
            "message": str(obs.attrs.get("msg_name", "?")),
            "from_system": str(obs.attrs.get("sysid", "?")),
            "from_component": str(obs.attrs.get("compid", "?")),
            "target_system": str(obs.attrs.get("target_system", "?")),
            "effect": effect,
        }

        # A COMMAND_LONG is only as interesting as the command it carries.
        command_name = str(obs.attrs.get("command_name", ""))
        if command_name:
            facts["command"] = command_name
            if str(obs.attrs.get("actuating", "0")) == "1":
                score = max(score, 0.70)
                category = "actuate"
        arm = str(obs.attrs.get("arm_action", ""))
        if arm:
            facts["arm_action"] = arm
            if arm == "DISARM":
                # Disarming an airborne multirotor cuts the motors.
                score, category = 0.85, "disarm"
        param = str(obs.attrs.get("param_id", ""))
        if param:
            facts["param_id"] = param
            facts["param_value"] = str(obs.attrs.get("param_value", ""))
            # SYSID_MYGCS names which ground station the vehicle obeys.
            # Rewriting it is how an injected link makes itself the operator.
            if param.upper() in ("SYSID_MYGCS", "SYSID_THISMAV"):
                score, category = 0.85, "takeover"
                facts["effect"] = (
                    "rewrites which ground station the vehicle accepts "
                    "commands from"
                )

        return InspectionResult(
            name=f"{self.name}.{category}",
            score=min(1.0, score),
            facts=facts,
            features={"actuating": float(obs.attrs.get("actuating", 0) or 0)},
            occurrences=1,
            loci=(obs.locus,) if obs.locus else (),
            notes=(
                "MAVLink has no authentication unless v2 signing is enabled, "
                "so reachability is authorisation",
                "not probed: confirming a command would mean sending one to "
                "an aircraft",
            ),
        )


class MavlinkPositionJump(Inspector):
    """A reported position that moved further than the airframe could fly.

    The discontinuity is computed by `capture/mavlink.py`, which holds the
    previous fix per system; this judges it. The threshold is an implied
    ground speed rather than a distance, because a 100 m step is unremarkable
    over ten seconds and impossible over 200 ms.

    WHAT THIS IS NOT. A jump is not proof of spoofing. A capture with a gap,
    a vehicle that genuinely lost and reacquired its fix, and a clock skew
    between reports all produce one. The finding states the implied speed and
    names the confirmation step.
    """

    name = "uav.position_jump"
    kinds = ("mavlink_message",)
    requires_attrs = ("jump_speed_m_s",)

    #: Fast for a fixed-wing UAV, impossible for a multirotor. Above this,
    #: the position source is more likely wrong than the vehicle fast.
    IMPLAUSIBLE_M_S = 120.0

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        try:
            implied = float(obs.attrs["jump_speed_m_s"])
            jump = float(obs.attrs.get("jump_m", 0.0))
            gap = float(obs.attrs.get("since_last_fix_s", 0.0))
        except (KeyError, TypeError, ValueError):
            return None

        limit = float(ctx.tunable("uav.max_speed_m_s", self.IMPLAUSIBLE_M_S))
        if implied < limit:
            return None

        # Scored on how far past plausible it is, on a log scale: 0.55 at the
        # limit, 0.75 at ten times it, 0.95 at a hundred.
        #
        # MONOTONIC ON PURPOSE. An earlier version saturated hard, on the
        # reasoning that a 400 km teleport is no more impossible than a 4 km
        # one. True for certainty, but `fold()` keeps the highest-SCORING
        # instance per name — so once several jumps hit the ceiling, the
        # facts retained came from whichever tied first rather than from the
        # worst. An operator shown one discontinuity should be shown the
        # largest.
        over = implied / limit
        score = min(0.95, 0.55 + 0.40 * min(1.0, math.log10(max(1.0, over)) / 2.0))

        return InspectionResult(
            name=self.name,
            score=score,
            facts={
                "from_system": str(obs.attrs.get("sysid", "?")),
                "jump_m": f"{jump:.0f}",
                "interval_s": f"{gap:.3f}",
                "implied_speed_m_s": f"{implied:.0f}",
                "plausible_limit_m_s": f"{limit:.0f}",
                "position": f"{obs.attrs.get('lat')},{obs.attrs.get('lon')}",
                "reported_ground_speed_m_s": str(
                    obs.attrs.get("ground_speed_m_s", "?")
                ),
            },
            features={
                "implied_speed_m_s": implied,
                "jump_m": jump,
                "over_limit": over,
            },
            occurrences=1,
            loci=(obs.locus,) if obs.locus else (),
            notes=(
                "the position source disagrees with physics — but a capture "
                "gap or a reacquired fix also produces this",
                "corroborate against the vehicle's own reported ground speed, "
                "which an injected position usually fails to match",
            ),
        )


class MavlinkUnsigned(Inspector):
    """MAVLink v2 without message signing.

    Recorded rather than alerted, because it is the default almost
    everywhere. It earns its place as the precondition the command rules
    depend on: an unsigned link is why a spoofed system id works at all, so
    a report that names an injected command should also say the link had no
    way to reject it.
    """

    name = "uav.unsigned_link"
    kinds = ("mavlink_message",)
    requires_attrs = ("mavlink_version", "signed")

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        version = str(obs.attrs.get("mavlink_version", ""))
        signed = str(obs.attrs.get("signed", "0")) == "1"
        if signed:
            return None

        if version == "2":
            detail = "v2 frames carry no signature, so signing is disabled"
        else:
            detail = "v1 has no signing mechanism at all"

        return self._finding(
            # Below every rule threshold: this is context, not a finding.
            score=0.20,
            facts={
                "mavlink_version": version,
                "signing": "absent",
                "detail": detail,
            },
            obs=obs,
            features={"signed": 0.0},
            notes=(
                "the usual default — reported so a command finding can say "
                "the link had no way to reject the sender",
            ),
        )
