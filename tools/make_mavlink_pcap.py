#!/usr/bin/env python3
"""Synthesise a MAVLink-over-UDP capture.

Cleartext and UDP, so this is the simplest fixture in the repo to frame — the
difficulty is entirely in the payload field order, which MAVLink sorts by
type size rather than by declaration order. Each builder writes its layout
out explicitly so it can be checked against the XML by eye.

Checksums are written as zero. The parser does not validate them (see
`capture/mavlink.py` for why), and computing them would mean embedding the
per-message CRC_EXTRA table.

    python3 tools/make_mavlink_pcap.py out/mav.pcap --profile normal
    python3 tools/make_mavlink_pcap.py out/mav.pcap --profile hijack
    python3 tools/make_mavlink_pcap.py out/mav.pcap --profile spoof
"""

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path
from typing import List, Tuple

GCS_IP = "10.40.0.10"
VEHICLE_IP = "10.40.0.50"
ATTACKER_IP = "10.40.0.99"
MAV_PORT = 14550
BASE_TS = 1_792_000_000.0

#: system ids
SYS_VEHICLE = 1
SYS_GCS = 255
SYS_ATTACKER = 42

#: Start of a short flight near Reykjavik, far from anywhere the fixtures
#: for other domains use.
HOME_LAT, HOME_LON = 64.1300000, -21.9400000

Frame = Tuple[float, bytes]


# --------------------------------------------------------------------------
# MAVLink framing
# --------------------------------------------------------------------------


def mavlink_v2(sysid: int, compid: int, msgid: int, payload: bytes,
               sequence: int, signed: bool = False) -> bytes:
    """A MAVLink v2 frame. Checksum zeroed — see the module docstring."""
    incompat = 0x01 if signed else 0x00
    header = struct.pack(
        "<BBBBBBB", 0xFD, len(payload), incompat, 0, sequence & 0xFF,
        sysid, compid,
    ) + msgid.to_bytes(3, "little")
    frame = header + payload + b"\x00\x00"
    if signed:
        frame += b"\x00" * 13
    return frame


def mavlink_v1(sysid: int, compid: int, msgid: int, payload: bytes,
               sequence: int) -> bytes:
    header = struct.pack(
        "<BBBBBB", 0xFE, len(payload), sequence & 0xFF, sysid, compid, msgid
    )
    return header + payload + b"\x00\x00"


# --------------------------------------------------------------------------
# payloads, in WIRE order (size-descending, not declaration order)
# --------------------------------------------------------------------------


def heartbeat(armed: bool = True, custom_mode: int = 4) -> bytes:
    # custom_mode(u32) type(u8) autopilot(u8) base_mode(u8) status(u8) ver(u8)
    base_mode = 0x81 if armed else 0x01
    return struct.pack("<IBBBBB", custom_mode, 2, 3, base_mode, 4, 3)


def global_position(lat: float, lon: float, alt_m: float,
                    boot_ms: int, vx: int = 500, vy: int = 0) -> bytes:
    # boot(u32) lat(i32) lon(i32) alt(i32) rel(i32) vx(i16) vy(i16) vz(i16) hdg(u16)
    return struct.pack(
        "<IiiiihhhH",
        boot_ms,
        int(lat * 1e7), int(lon * 1e7),
        int(alt_m * 1000), int(alt_m * 1000),
        vx, vy, 0, 9000,
    )


def command_long(command: int, target: int = SYS_VEHICLE,
                 param1: float = 0.0) -> bytes:
    # param1..7(f32) command(u16) target_system(u8) target_component(u8)
    # confirmation(u8)
    return (
        struct.pack("<7f", param1, 0, 0, 0, 0, 0, 0)
        + struct.pack("<HBBB", command, target, 1, 0)
    )


def set_mode(custom_mode: int, target: int = SYS_VEHICLE) -> bytes:
    # custom_mode(u32) target_system(u8) base_mode(u8)
    return struct.pack("<IBB", custom_mode, target, 0x01)


def param_set(name: str, value: float, target: int = SYS_VEHICLE) -> bytes:
    # value(f32) target_system(u8) target_component(u8) id(char[16]) type(u8)
    return (
        struct.pack("<fBB", value, target, 1)
        + name.encode("ascii")[:16].ljust(16, b"\x00")
        + struct.pack("<B", 9)
    )


# --------------------------------------------------------------------------
# UDP framing
# --------------------------------------------------------------------------


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + payload


def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 17, 0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    ) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def datagram(ts: float, src: str, dst: str, sport: int,
             payload: bytes) -> Frame:
    return (ts, _eth(_ipv4(src, dst, _udp(sport, MAV_PORT, payload))))


# --------------------------------------------------------------------------
# profiles
# --------------------------------------------------------------------------


def profile_normal(rng: random.Random) -> List[Frame]:
    """A vehicle streaming telemetry and a GCS heartbeating back.

    1 Hz heartbeats, 5 Hz position at a plausible 5 m/s ground speed. This
    is the baseline a deployment learns from.
    """
    frames: List[Frame] = []
    ts = BASE_TS
    sequence = 0
    lat, lon = HOME_LAT, HOME_LON

    for tick in range(60):
        # Vehicle heartbeat, 1 Hz.
        frames.append(datagram(
            ts, VEHICLE_IP, GCS_IP, 14551,
            mavlink_v2(SYS_VEHICLE, 1, 0, heartbeat(), sequence),
        ))
        sequence += 1
        # GCS heartbeat back.
        frames.append(datagram(
            ts + 0.01, GCS_IP, VEHICLE_IP, 14552,
            mavlink_v2(SYS_GCS, 190, 0, heartbeat(armed=False, custom_mode=0),
                       sequence),
        ))
        sequence += 1

        # Position at 5 Hz, moving north at ~5 m/s. 5 m/s for 0.2s is about
        # 1e-5 degrees of latitude.
        for step in range(5):
            lat += 0.0000090
            lon += 0.0000015
            frames.append(datagram(
                ts + 0.1 + step * 0.2, VEHICLE_IP, GCS_IP, 14551,
                mavlink_v2(SYS_VEHICLE, 1, 33,
                           global_position(lat, lon, 45.0, tick * 1000 + step * 200),
                           sequence),
            ))
            sequence += 1
        ts += 1.0 + rng.uniform(-0.004, 0.004)

    frames.sort(key=lambda f: f[0])
    return frames


def profile_hijack(rng: random.Random) -> List[Frame]:
    """Command injection from a system id the vehicle has never heard from.

    Mode change, then disarm in flight, then a parameter write. Disarming an
    airborne multirotor stops the motors.
    """
    frames = profile_normal(rng)

    ts = BASE_TS + 30.0
    sequence = 200
    for payload, msgid in (
        (set_mode(0), 11),                               # back to STABILIZE
        (command_long(400, param1=0.0), 76),             # ARM_DISARM: disarm
        (param_set("SYSID_MYGCS", 42.0), 23),            # take over the link
        (command_long(21), 76),                          # NAV_LAND
    ):
        frames.append(datagram(
            ts, ATTACKER_IP, VEHICLE_IP, 14553,
            mavlink_v2(SYS_ATTACKER, 190, msgid, payload, sequence),
        ))
        sequence += 1
        ts += 0.25

    frames.sort(key=lambda f: f[0])
    return frames


def profile_spoof(rng: random.Random) -> List[Frame]:
    """A GPS position discontinuity — the vehicle appears to teleport.

    Positions continue at 5 Hz, but one fix lands ~4 km away. No airframe
    covers that in 200 ms, so either the capture is wrong or the position
    source is lying.
    """
    frames = profile_normal(rng)

    ts = BASE_TS + 40.0
    sequence = 400
    lat, lon = HOME_LAT + 0.0027, HOME_LON + 0.00045

    for step in range(10):
        if step == 5:
            # ~4 km east in one 200 ms interval.
            lon += 0.082
        else:
            lat += 0.0000090
            lon += 0.0000015
        frames.append(datagram(
            ts + step * 0.2, VEHICLE_IP, GCS_IP, 14551,
            mavlink_v2(SYS_VEHICLE, 1, 33,
                       global_position(lat, lon, 45.0, 40_000 + step * 200),
                       sequence),
        ))
        sequence += 1

    frames.sort(key=lambda f: f[0])
    return frames


PROFILES = {
    "normal": profile_normal,
    "hijack": profile_hijack,
    "spoof": profile_spoof,
}


# --------------------------------------------------------------------------


def write_pcap(path: Path, frames: List[Frame]) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, data in frames:
            seconds = int(ts)
            handle.write(struct.pack(
                "<IIII", seconds, int((ts - seconds) * 1_000_000),
                len(data), len(data)
            ))
            handle.write(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="normal")
    parser.add_argument("--seed", type=int, default=20261024)
    args = parser.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    frames = PROFILES[args.profile](random.Random(args.seed))
    write_pcap(out, frames)
    print(f"{out}: {len(frames)} frames, profile={args.profile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
