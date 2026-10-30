"""Industrial control inspectors — Modbus/TCP and DNP3.

WHAT IS DIFFERENT ABOUT ICS. On a web target, a request is suspicious because
of what it contains. On a control network, a request is suspicious because of
what it DOES and who sent it. Neither Modbus nor DNP3 over TCP has any
authentication — a host that can reach port 502 or 20000 can command the
device — so the protocol-level finding is never "this is malformed", it is
"this host is writing, and it has never written before".

That shape means these inspectors deliberately do little on their own. They
classify a message; the rules combine that with `rarity` to ask whether the
source is new. A write from the established HMI is Tuesday. The same write
from a host nobody has seen is the finding.

SAFETY. Nothing here probes. Reading a register to confirm a finding would
mean issuing a command on a live control network, which is exactly the thing
that must never be automated.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from core.inspect import Inspector
from core.model import Context, InspectionResult, Observation

__all__ = [
    "ModbusCommand", "ModbusException", "Dnp3Command", "Dnp3Indications",
]


class ModbusCommand(Inspector):
    """A Modbus request that changes state, or asks the device about itself.

    Classified, not judged. Severity comes from the rules, which weigh this
    against `rarity` — the question is not "was there a write" but "was there
    a write from somewhere unexpected".

    Diagnostics (function 8) are scored alongside writes rather than with
    reads, because sub-function 1 restarts communications and sub-function 4
    puts the device in listen-only mode. Those are availability actions on a
    process network, not inspection.
    """

    name = "ics.modbus_command"
    kinds = ("modbus_request",)
    requires_attrs = ("category", "fc")

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        category = str(obs.attrs.get("category", ""))
        if category not in ("write", "control"):
            return None

        fc = str(obs.attrs.get("fc", "?"))
        fc_name = str(obs.attrs.get("fc_name", f"function {fc}"))
        unit = str(obs.attrs.get("unit", "?"))

        if category == "write":
            score = 0.60
            effect = "writes to the process image"
        else:
            score = 0.45
            effect = "device management or diagnostics"

        facts: Dict[str, str] = {
            "function_code": fc,
            "function": fc_name,
            "category": category,
            "unit_id": unit,
            "effect": effect,
        }
        reference = str(obs.attrs.get("reference", ""))
        if reference:
            facts["reference"] = reference

        return InspectionResult(
            # A CATEGORY-SCOPED NAME, not `self.name`. `fold()` keeps the
            # worst result per name, so emitting every category under one
            # name silently discarded all but the highest-scoring one — a
            # capture containing both a write and a diagnostic reported only
            # the write, and any rule gating on the other could never fire.
            # Distinct consequences need distinct names, exactly as `Fanout`
            # gets one name per attribute.
            name=f"{self.name}.{category}",
            score=min(1.0, score),
            facts=facts,
            secret_facts=(),
            features={
                "is_write": 1.0 if category == "write" else 0.0,
                "function_code": float(fc) if fc.isdigit() else -1.0,
            },
            occurrences=1,
            loci=(obs.locus,) if obs.locus else (),
            notes=(
                "Modbus has no authentication — reachability is authorisation, "
                "so the question is whether this source is expected",
                "not probed: confirming a write would mean issuing a command "
                "on a live control network",
            ),
        )


class ModbusException(Inspector):
    """An exception response.

    One exception is a mistyped address. Dozens are a scanner: walking unit
    ids collects "gateway target device failed to respond" from every unit
    that does not exist, and walking function codes collects "illegal
    function" from every one the device does not implement. The count is the
    signal, so this leans entirely on folding — per-message it says almost
    nothing.
    """

    name = "ics.modbus_exception"
    kinds = ("modbus_response",)
    requires_attrs = ("exception",)

    #: Codes that specifically indicate probing rather than a bad value.
    _ENUMERATION_CODES = {
        "1": "Illegal Function — the device does not implement this code",
        "2": "Illegal Data Address — the register does not exist",
        "11": "Gateway Target Device Failed To Respond — no such unit",
    }

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        code = str(obs.attrs.get("exception", ""))
        if not code:
            return None

        meaning = self._ENUMERATION_CODES.get(
            code, str(obs.attrs.get("exception_name", f"code {code}"))
        )
        # Scored low per message on purpose. A single exception is noise; the
        # rules key on `occurrences`, which folding supplies.
        score = 0.20 if code in self._ENUMERATION_CODES else 0.10

        return self._finding(
            score=score,
            facts={
                "exception_code": code,
                "exception": meaning,
                "function_code": str(obs.attrs.get("fc", "?")),
                "unit_id": str(obs.attrs.get("unit", "?")),
            },
            obs=obs,
            features={
                "enumeration_shaped": 1.0 if code in self._ENUMERATION_CODES else 0.0,
            },
            notes=(
                "one exception is a typo; many are enumeration — the count "
                "carries the signal, not this message",
            ),
        )


# --------------------------------------------------------------------------
# DNP3
# --------------------------------------------------------------------------


class Dnp3Command(Inspector):
    """A DNP3 application function that acts on the process or the device.

    DNP3 grades more finely than Modbus, and the grades matter because the
    consequences differ in kind rather than degree:

        select    arms a control point; harmless alone, half of a sequence
        operate   closes a breaker, moves a setpoint — physical effect
        write     changes configuration
        restart   COLD_RESTART, WARM_RESTART, STOP_APPL — the device stops
        suppress  DISABLE_UNSOLICITED — the device stops REPORTING, which
                  blinds the real master without touching the process

    `suppress` is the one worth dwelling on. It is not an attack on the
    plant; it is an attack on the operator's view of the plant, and it is
    commonly a precursor. Scored close to `operate` for that reason.
    """

    name = "ics.dnp3_command"
    kinds = ("dnp3_request",)
    requires_attrs = ("category", "fc")

    _GRADES = {
        "operate": (0.70, "commands a control point — physical effect"),
        "restart": (0.70, "stops or restarts the device"),
        "suppress": (0.65, "stops the device reporting, blinding the master"),
        "write": (0.60, "changes device configuration"),
        "select": (0.40, "arms a control point; half of a select-operate pair"),
    }

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        category = str(obs.attrs.get("category", ""))
        grade = self._GRADES.get(category)
        if grade is None:
            return None
        score, effect = grade

        facts: Dict[str, str] = {
            "function_code": str(obs.attrs.get("fc", "?")),
            "function": str(obs.attrs.get("fc_name", "?")),
            "category": category,
            "effect": effect,
            "link_source": str(obs.attrs.get("link_src", "?")),
            "link_destination": str(obs.attrs.get("link_dst", "?")),
        }

        return InspectionResult(
            # Per-category name — see the note in ModbusCommand. DNP3 makes
            # this unavoidable: a single capture routinely carries a restart
            # AND a reporting-suppression command, and under one name the
            # lower-scoring suppression vanished along with the rule that
            # was meant to catch it.
            name=f"{self.name}.{category}",
            score=min(1.0, score),
            facts=facts,
            secret_facts=(),
            features={"category_score": score},
            occurrences=1,
            loci=(obs.locus,) if obs.locus else (),
            notes=(
                "DNP3 over TCP has no transport security and no "
                "authentication — reachability is authorisation",
                "not probed: confirming a control command would mean issuing "
                "one on a live plant",
            ),
        )


class Dnp3Indications(Inspector):
    """Internal Indications flags an outstation sets in its responses.

    Worth its own inspector because these report the DEVICE'S OWN view of
    what has happened to it, independently of what the attacker sent. A
    `device restart` bit appearing mid-capture is the outstation saying it
    rebooted — evidence of the effect rather than of the command, and it
    survives even if the command itself was not captured.
    """

    name = "ics.dnp3_indications"
    kinds = ("dnp3_response",)
    requires_attrs = ("iin_flags",)

    _WEIGHT = {
        "device restart": 0.70,
        "event buffer overflow": 0.50,
        "device trouble": 0.45,
        "function not implemented": 0.25,
        "requested objects unknown": 0.25,
        "parameter out of range": 0.20,
    }

    def inspect(self, obs: Observation, ctx: Context) -> Optional[InspectionResult]:
        raw = str(obs.attrs.get("iin_flags", ""))
        flags = [f.strip() for f in raw.split(",") if f.strip()]
        if not flags:
            return None

        score = max((self._WEIGHT.get(f, 0.15) for f in flags), default=0.15)

        return self._finding(
            score=score,
            facts={
                "indications": ", ".join(flags),
                "iin": str(obs.attrs.get("iin", "")),
                "responding_to_function": str(obs.attrs.get("fc", "?")),
            },
            obs=obs,
            features={
                "restarted": 1.0 if "device restart" in flags else 0.0,
                "flag_count": float(len(flags)),
            },
            notes=(
                "reported by the outstation about itself, so it evidences "
                "the effect rather than the command",
            ),
        )
