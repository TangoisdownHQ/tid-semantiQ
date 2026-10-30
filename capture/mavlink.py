"""MAVLink — a NATIVE parser, because Wireshark has no dissector for it.

WHY THIS ONE IS DIFFERENT. Modbus and DNP3 were onboarded as tshark field
lists: Wireshark dissects both, so neither needed a parser. MAVLink does not
work that way — Wireshark ships no MAVLink dissector. The one that exists is
a Lua plugin generated from the MAVLink XML definitions by the MAVLink
toolchain, and it is not part of a stock install.

So this demonstrates the other half of the capture contract. Modbus and DNP3
proved "a domain can be a field list"; MAVLink proves "a domain can be a
native parser", and that nothing above `capture/` can tell the difference.
`Observation` comes out the same either way.

CHECKSUMS ARE NOT VALIDATED, deliberately. MAVLink's CRC includes a
per-message CRC_EXTRA byte derived from the message's field definitions, so
checking it would mean embedding a msgid -> CRC_EXTRA table generated from
the XML — a large table that goes stale with every dialect. The cost of
skipping it is that a corrupt frame may parse as a valid message; the cost of
requiring it would be dropping every message from any dialect not in the
table. For an analysis tool reading an adversarial capture, decoding too much
is the better failure: a malformed frame produces a visible oddity, whereas a
dropped frame produces silence.

FIELD ORDER. MAVLink does not serialise fields in declaration order. It
sorts by type size, largest first, preserving declaration order within a
size class. So COMMAND_LONG goes param1..7 (4 bytes each), then command
(2), then target_system, target_component, confirmation (1 each) — NOT the
order the XML lists them in. Getting this wrong yields plausible-looking
nonsense rather than an error, which is why each layout below is written out
explicitly.
"""

from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any, Dict, Iterator, List, NamedTuple, Optional, Tuple

from capture.base import CaptureSource
from capture.decode import PROTO_UDP, decode_ip, decode_udp
from capture.pcapfile import read_frames
from core.model import Channel, Direction, Entity, Locus, Observation

__all__ = ["MavlinkSource", "MavlinkFrame", "parse_frames", "MAV_CMD", "MESSAGES"]


MAGIC_V1 = 0xFE
MAGIC_V2 = 0xFD
#: incompat flag 0x01 means a 13-octet signature follows the checksum
INCOMPAT_SIGNED = 0x01

#: Default MAVLink UDP ports. Used only to decide which datagrams to try;
#: `MavlinkSource(ports=...)` overrides for a non-standard link.
DEFAULT_PORTS = (14550, 14551, 14555, 14580)

#: Message ids this parser decodes beyond the header. Everything else is
#: reported by id alone, which is still enough for cadence and cardinality.
MESSAGES = {
    0: "HEARTBEAT",
    1: "SYS_STATUS",
    11: "SET_MODE",
    20: "PARAM_REQUEST_READ",
    23: "PARAM_SET",
    33: "GLOBAL_POSITION_INT",
    76: "COMMAND_LONG",
    77: "COMMAND_ACK",
}

#: MAV_CMD values worth naming. The arm/disarm and reboot commands are the
#: ones that take an aircraft out of the sky.
MAV_CMD = {
    16: "NAV_WAYPOINT",
    20: "NAV_RETURN_TO_LAUNCH",
    21: "NAV_LAND",
    22: "NAV_TAKEOFF",
    176: "DO_SET_MODE",
    252: "OVERRIDE_GOTO",
    246: "PREFLIGHT_REBOOT_SHUTDOWN",
    400: "COMPONENT_ARM_DISARM",
}
#: Commands that change flight state rather than query it.
ACTUATING_CMDS = {20, 21, 22, 176, 246, 252, 400}


class MavlinkFrame(NamedTuple):
    version: int
    sequence: int
    system_id: int
    component_id: int
    message_id: int
    payload: bytes
    signed: bool
    length: int          # total frame length on the wire


def parse_frames(data: bytes) -> List[MavlinkFrame]:
    """Every MAVLink frame in one UDP payload.

    A datagram may carry several frames back to back, so this scans rather
    than assuming one. Resynchronisation is by magic byte: anything that is
    not a plausible frame start is skipped a byte at a time, which is what a
    receiver does on a lossy link.
    """
    frames: List[MavlinkFrame] = []
    offset = 0
    end = len(data)

    while offset < end:
        magic = data[offset]
        if magic == MAGIC_V1:
            if offset + 8 > end:
                break
            length = data[offset + 1]
            total = 8 + length
            if offset + total > end:
                break
            frames.append(MavlinkFrame(
                version=1,
                sequence=data[offset + 2],
                system_id=data[offset + 3],
                component_id=data[offset + 4],
                message_id=data[offset + 5],
                payload=data[offset + 6:offset + 6 + length],
                signed=False,
                length=total,
            ))
            offset += total
            continue

        if magic == MAGIC_V2:
            if offset + 12 > end:
                break
            length = data[offset + 1]
            incompat = data[offset + 2]
            signed = bool(incompat & INCOMPAT_SIGNED)
            total = 12 + length + (13 if signed else 0)
            if offset + total > end:
                break
            message_id = int.from_bytes(data[offset + 7:offset + 10], "little")
            frames.append(MavlinkFrame(
                version=2,
                sequence=data[offset + 4],
                system_id=data[offset + 5],
                component_id=data[offset + 6],
                message_id=message_id,
                payload=data[offset + 10:offset + 10 + length],
                signed=signed,
                length=total,
            ))
            offset += total
            continue

        offset += 1

    return frames


# --------------------------------------------------------------------------
# payload decoders
# --------------------------------------------------------------------------
#
# Wire order is size-descending, NOT declaration order. Each layout is
# spelled out so the ordering is checkable against the XML by eye.


def _heartbeat(payload: bytes) -> Dict[str, Any]:
    # custom_mode(u32) type(u8) autopilot(u8) base_mode(u8) status(u8) ver(u8)
    if len(payload) < 9:
        return {}
    custom_mode, kind, autopilot, base_mode, status, version = struct.unpack(
        "<IBBBBB", payload[:9]
    )
    return {
        "vehicle_type": str(kind),
        "autopilot": str(autopilot),
        "base_mode": str(base_mode),
        "custom_mode": str(custom_mode),
        "system_status": str(status),
        "mavlink_version": str(version),
        "armed": "1" if base_mode & 0x80 else "0",
    }


def _set_mode(payload: bytes) -> Dict[str, Any]:
    # custom_mode(u32) target_system(u8) base_mode(u8)
    if len(payload) < 6:
        return {}
    custom_mode, target, base_mode = struct.unpack("<IBB", payload[:6])
    return {
        "target_system": str(target),
        "base_mode": str(base_mode),
        "custom_mode": str(custom_mode),
    }


def _param_set(payload: bytes) -> Dict[str, Any]:
    # value(f32) target_system(u8) target_component(u8) id(char[16]) type(u8)
    if len(payload) < 23:
        return {}
    value, target, component = struct.unpack("<fBB", payload[:6])
    name = payload[6:22].split(b"\x00")[0].decode("ascii", "replace")
    return {
        "param_id": name,
        "param_value": f"{value:g}",
        "target_system": str(target),
        "target_component": str(component),
    }


def _global_position(payload: bytes) -> Dict[str, Any]:
    # boot_ms(u32) lat(i32) lon(i32) alt(i32) rel_alt(i32)
    # vx(i16) vy(i16) vz(i16) hdg(u16)
    if len(payload) < 28:
        return {}
    boot, lat, lon, alt, rel_alt, vx, vy, vz, hdg = struct.unpack(
        "<IiiiihhhH", payload[:28]
    )
    return {
        "time_boot_ms": str(boot),
        # MAVLink carries position as degrees x 1e7 and altitude in mm.
        "lat": f"{lat / 1e7:.7f}",
        "lon": f"{lon / 1e7:.7f}",
        "alt_m": f"{alt / 1000.0:.2f}",
        "relative_alt_m": f"{rel_alt / 1000.0:.2f}",
        "ground_speed_m_s": f"{math.hypot(vx, vy) / 100.0:.2f}",
        "heading_deg": f"{hdg / 100.0:.1f}" if hdg != 0xFFFF else "unknown",
    }


def _command_long(payload: bytes) -> Dict[str, Any]:
    # param1..7(f32 x7) command(u16) target_system(u8) target_component(u8)
    # confirmation(u8)
    if len(payload) < 33:
        return {}
    values = struct.unpack("<7f", payload[:28])
    command, target, component, confirmation = struct.unpack(
        "<HBBB", payload[28:33]
    )
    out = {
        "command": str(command),
        "command_name": MAV_CMD.get(command, f"MAV_CMD {command}"),
        "target_system": str(target),
        "target_component": str(component),
        "confirmation": str(confirmation),
        "actuating": "1" if command in ACTUATING_CMDS else "0",
    }
    for index, value in enumerate(values, start=1):
        if value:
            out[f"param{index}"] = f"{value:g}"
    # ARM_DISARM encodes the action in param1: 1 arms, 0 disarms.
    if command == 400:
        out["arm_action"] = "arm" if values[0] >= 0.5 else "DISARM"
    return out


_DECODERS = {
    0: _heartbeat,
    11: _set_mode,
    23: _param_set,
    33: _global_position,
    76: _command_long,
}


# --------------------------------------------------------------------------
# geography
# --------------------------------------------------------------------------


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in metres.

    Needed because the interesting GPS finding is a DISCONTINUITY — a
    position that moved further between two reports than the airframe
    could have flown. Comparing raw degrees would make a jump near the poles
    look larger than the same jump at the equator.
    """
    radius = 6_371_000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = phi2 - phi1
    dlambda = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    return 2 * radius * math.asin(min(1.0, math.sqrt(a)))


# --------------------------------------------------------------------------
# the source
# --------------------------------------------------------------------------


class MavlinkSource(CaptureSource):
    """Read MAVLink over UDP from a pcap, with no external tools.

    CHANNEL GRANULARITY. Identity is the (system, destination) pair:
    `initiator` is a `mavlink_sysid` entity of `sysid.compid`, not an IP.
    That is what makes `rarity.novel` answer the question that matters —
    "a system id that has never commanded this vehicle just did" — because
    MAVLink identity is the system id, and an injected command may well
    arrive from a spoofed or irrelevant address.

    Message id stays in `attrs` so `Fanout` can count it; putting it in
    `dims` would make message-id cardinality uncountable, which is the
    mistake already made and corrected for DNS, HTTP, Modbus and DNP3.
    """

    domain = "mavlink"

    def __init__(
        self,
        path: Path | str,
        ports: Tuple[int, ...] = DEFAULT_PORTS,
        any_port: bool = False,
    ):
        self.path = Path(path)
        self.ports = ports
        # A test link often runs on an arbitrary port. `any_port` tries every
        # datagram, which costs a magic-byte check per packet.
        self.any_port = any_port
        #: (sysid, compid) -> (timestamp, lat, lon) of the last position
        self._last_position: Dict[str, Tuple[float, float, float]] = {}
        self.stats = {
            "frames": 0, "datagrams": 0, "messages": 0, "unsigned_v2": 0,
        }

    def observations(self) -> Iterator[Observation]:
        for frame_number, ts, linktype, frame in read_frames(self.path):
            self.stats["frames"] += 1
            packet = decode_ip(linktype, frame)
            if packet is None or packet.proto != PROTO_UDP:
                continue
            segment = decode_udp(packet.payload)
            if segment is None or not segment.payload:
                continue
            if not self.any_port and not (
                segment.sport in self.ports or segment.dport in self.ports
            ):
                continue
            self.stats["datagrams"] += 1

            for message in parse_frames(segment.payload):
                self.stats["messages"] += 1
                if message.version == 2 and not message.signed:
                    self.stats["unsigned_v2"] += 1
                yield self._observation(
                    message, ts, packet, segment, frame_number
                )

    def _observation(self, message: MavlinkFrame, ts: float, packet,
                     segment, frame_number: int) -> Observation:
        name = MESSAGES.get(message.message_id, f"MSG {message.message_id}")
        attrs: Dict[str, Any] = {
            "encrypted": False,       # MAVLink has no transport encryption
            "mavlink_version": str(message.version),
            "sysid": str(message.system_id),
            "compid": str(message.component_id),
            "msgid": str(message.message_id),
            "msg_name": name,
            "signed": "1" if message.signed else "0",
            "sequence": str(message.sequence),
            "dst_ip": packet.dst,
            "dport": str(segment.dport),
        }

        decoder = _DECODERS.get(message.message_id)
        if decoder is not None:
            attrs.update(decoder(message.payload))

        # Position discontinuity is derived HERE rather than in a primitive,
        # because this is the layer holding the previous fix per system. It
        # is the same move as burst assembly and the connection warm-up flag:
        # the capture plugin computes what it alone has the state to compute,
        # and an inspector judges the result.
        if message.message_id == 33 and "lat" in attrs:
            key = f"{message.system_id}.{message.component_id}"
            lat, lon = float(attrs["lat"]), float(attrs["lon"])
            previous = self._last_position.get(key)
            if previous is not None:
                prev_ts, prev_lat, prev_lon = previous
                gap = max(1e-3, ts - prev_ts)
                jump = haversine_m(prev_lat, prev_lon, lat, lon)
                attrs["jump_m"] = f"{jump:.1f}"
                attrs["jump_speed_m_s"] = f"{jump / gap:.1f}"
                attrs["since_last_fix_s"] = f"{gap:.3f}"
            self._last_position[key] = (ts, lat, lon)

        return Observation(
            ts=ts,
            channel=Channel(
                domain="mavlink",
                dims={"proto": "mavlink"},
                initiator=Entity(
                    "mavlink_sysid",
                    f"{message.system_id}.{message.component_id}",
                ),
                responder=Entity("ip", packet.dst),
            ),
            # MAVLink is a telemetry stream rather than a request/response
            # protocol, so every message is EGRESS from its system. There is
            # no pair to be the other side of.
            direction=Direction.EGRESS,
            size=message.length,
            kind="mavlink_message",
            wire_size=message.length,
            attrs=attrs,
            locus=Locus(source=self.path.name, frames=(frame_number,)),
        )
