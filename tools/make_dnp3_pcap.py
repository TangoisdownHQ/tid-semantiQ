#!/usr/bin/env python3
"""Synthesise a DNP3 (IEEE 1815) capture over TCP.

Harder to fabricate than Modbus, and the difficulty is instructive: DNP3's
data link layer carries a CRC over the header AND a separate CRC after every
16-byte block of user data. Wireshark validates them, so a frame with wrong
CRCs dissects as a malformed link frame and never reaches the application
layer — meaning none of the fields the analyzer needs would appear.

Frame layout, for reference while reading the builders:

    link      0x05 0x64 | LEN | CTRL | DEST(2 LE) | SRC(2 LE) | CRC(2 LE)
              LEN counts CTRL..SRC plus user data, excluding start, LEN
              itself and every CRC
    transport 1 octet: FIR | FIN | SEQ
    app       APP_CTRL | FUNC | [IIN(2) on responses] | objects

    python3 tools/make_dnp3_pcap.py out/dnp3.pcap --profile normal
    python3 tools/make_dnp3_pcap.py out/dnp3.pcap --profile control
    python3 tools/make_dnp3_pcap.py out/dnp3.pcap --profile restart
"""

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path
from typing import List, Tuple

MASTER = "10.30.0.10"
OUTSTATION = "10.30.0.60"
ROGUE = "10.30.0.88"
DNP3_PORT = 20000
BASE_TS = 1_791_000_000.0

# link-layer addresses
ADDR_MASTER = 1
ADDR_OUTSTATION = 10
ADDR_ROGUE = 7

# application function codes
FC_CONFIRM = 0
FC_READ = 1
FC_WRITE = 2
FC_SELECT = 3
FC_OPERATE = 4
FC_DIRECT_OPERATE = 5
FC_DIRECT_OPERATE_NR = 6
FC_COLD_RESTART = 13
FC_WARM_RESTART = 14
FC_STOP_APPL = 18
FC_ENABLE_UNSOLICITED = 20
FC_DISABLE_UNSOLICITED = 21
FC_RESPONSE = 129
FC_UNSOLICITED = 130

Frame = Tuple[float, bytes]


# --------------------------------------------------------------------------
# DNP3 CRC
# --------------------------------------------------------------------------


def dnp3_crc(data: bytes) -> int:
    """DNP3 CRC-16: polynomial 0x3D65 reflected (0xA6BC), init 0, final
    complement, little-endian on the wire.

    Not optional. Wireshark checks it, and a bad CRC stops the dissector at
    the link layer — every application field the analyzer needs would simply
    be absent, which looks exactly like "DNP3 is not supported here".
    """
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _with_crc(block: bytes) -> bytes:
    return block + struct.pack("<H", dnp3_crc(block))


def dnp3_frame(control: int, destination: int, source: int,
               user_data: bytes) -> bytes:
    """A complete link frame, CRCs included."""
    length = 5 + len(user_data)
    header = struct.pack("<BBBBHH", 0x05, 0x64, length, control,
                         destination, source)
    out = _with_crc(header)
    # User data is CRC'd in blocks of at most 16 octets.
    for offset in range(0, len(user_data), 16):
        out += _with_crc(user_data[offset:offset + 16])
    return out


# --------------------------------------------------------------------------
# application fragments
# --------------------------------------------------------------------------


#: transport header: FIR + FIN, sequence 0 — a single-fragment message
_TRANSPORT = 0xC0


def _request(function: int, objects: bytes = b"", seq: int = 0) -> bytes:
    # app control: FIR | FIN | sequence
    app_control = 0xC0 | (seq & 0x0F)
    return bytes([_TRANSPORT, app_control, function]) + objects


def _response(function: int, iin: int = 0x0000, objects: bytes = b"",
              seq: int = 0, unsolicited: bool = False) -> bytes:
    app_control = 0xC0 | (0x10 if unsolicited else 0x00) | (seq & 0x0F)
    return (
        bytes([_TRANSPORT, app_control, function])
        + struct.pack("<H", iin)
        + objects
    )


def _object_header(group: int, variation: int, qualifier: int,
                   payload: bytes = b"") -> bytes:
    return bytes([group, variation, qualifier]) + payload


#: Read class 1 data — the ordinary poll. Qualifier 0x06 is "all objects".
READ_CLASS1 = _object_header(60, 2, 0x06)
#: Binary output command, group 12 variation 1, one index, 8-octet CROB.
#: Control code 0x03 is LATCH_ON.
def crob(index: int, control_code: int = 0x03) -> bytes:
    body = struct.pack(
        "<BBBIIB", control_code, 1, 0, 100, 100, 0
    )
    # qualifier 0x17 = 8-bit index count + index prefix
    return _object_header(12, 1, 0x17, bytes([1, index]) + body)


#: Analogue input response object, group 30 variation 1, index range 0-1.
ANALOG_RESPONSE = _object_header(
    30, 1, 0x00, struct.pack("<BBii", 0, 1, 1234, 5678)
)


# --------------------------------------------------------------------------
# TCP framing
# --------------------------------------------------------------------------


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + payload


def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 6, 0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    ) + payload


def _tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
         payload: bytes = b"") -> bytes:
    return struct.pack(
        ">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0
    ) + payload


class Conversation:
    """One TCP connection to an outstation, correctly sequenced."""

    def __init__(self, client: str, port: int, start: float):
        self.client = client
        self.port = port
        self.frames: List[Frame] = []
        self.c_seq = 1000
        self.s_seq = 7000
        self._emit(start, True, 0x02)
        self.c_seq += 1
        self._emit(start + 0.0005, False, 0x12)
        self.s_seq += 1
        self._emit(start + 0.001, True, 0x10)

    def _emit(self, ts: float, from_client: bool, flags: int,
              payload: bytes = b"") -> None:
        if from_client:
            packet = _tcp(self.port, DNP3_PORT, self.c_seq, self.s_seq,
                          flags, payload)
            self.frames.append((ts, _eth(_ipv4(self.client, OUTSTATION, packet))))
            self.c_seq += len(payload)
        else:
            packet = _tcp(DNP3_PORT, self.port, self.s_seq, self.c_seq,
                          flags, payload)
            self.frames.append((ts, _eth(_ipv4(OUTSTATION, self.client, packet))))
            self.s_seq += len(payload)

    def request(self, ts: float, source: int, user_data: bytes) -> None:
        # control 0xC4: DIR=1, PRM=1, function 4 (unconfirmed user data)
        self._emit(ts, True, 0x18,
                   dnp3_frame(0xC4, ADDR_OUTSTATION, source, user_data))

    def response(self, ts: float, destination: int, user_data: bytes) -> None:
        # control 0x44: DIR=0, PRM=1, function 4
        self._emit(ts, False, 0x18,
                   dnp3_frame(0x44, destination, ADDR_OUTSTATION, user_data))

    def close(self, ts: float) -> None:
        self._emit(ts, True, 0x11)
        self._emit(ts + 0.001, False, 0x11)


# --------------------------------------------------------------------------
# profiles
# --------------------------------------------------------------------------


def profile_normal(rng: random.Random) -> List[Frame]:
    """A master polling an outstation for class 1 data every 2 seconds."""
    conv = Conversation(MASTER, 49500, BASE_TS)
    ts = BASE_TS + 0.01
    for cycle in range(40):
        conv.request(ts, ADDR_MASTER, _request(FC_READ, READ_CLASS1,
                                               seq=cycle % 16))
        conv.response(ts + 0.006 + rng.uniform(-0.001, 0.001), ADDR_MASTER,
                      _response(FC_RESPONSE, 0x0000, ANALOG_RESPONSE,
                                seq=cycle % 16))
        ts += 2.0 + rng.uniform(-0.01, 0.01)
    conv.close(ts)
    return conv.frames


def profile_control(rng: random.Random) -> List[Frame]:
    """Normal polling, then control commands from an unexpected host.

    SELECT-then-OPERATE is the two-step DNP3 control sequence;
    DIRECT_OPERATE does it in one. Either way a binary output is being
    latched on a physical device. ATT&CK for ICS T0855 / T0831.
    """
    frames = profile_normal(rng)

    rogue = Conversation(ROGUE, 51500, BASE_TS + 21.0)
    ts = BASE_TS + 21.1
    rogue.request(ts, ADDR_ROGUE, _request(FC_SELECT, crob(3), seq=1))
    rogue.response(ts + 0.005, ADDR_ROGUE, _response(FC_RESPONSE, 0x0000, seq=1))
    rogue.request(ts + 0.2, ADDR_ROGUE, _request(FC_OPERATE, crob(3), seq=2))
    rogue.response(ts + 0.205, ADDR_ROGUE, _response(FC_RESPONSE, 0x0000, seq=2))
    rogue.request(ts + 0.4, ADDR_ROGUE,
                  _request(FC_DIRECT_OPERATE, crob(5), seq=3))
    rogue.response(ts + 0.405, ADDR_ROGUE, _response(FC_RESPONSE, 0x0000, seq=3))
    rogue.close(ts + 0.6)

    frames += rogue.frames
    frames.sort(key=lambda f: f[0])
    return frames


def profile_restart(rng: random.Random) -> List[Frame]:
    """An availability attack: silence the outstation, then restart it.

    DISABLE_UNSOLICITED stops the device volunteering events, which blinds
    the real master; COLD_RESTART reboots it. Together they are a denial of
    view followed by a denial of control. T0814 / T0816 / T0878.
    """
    frames = profile_normal(rng)

    rogue = Conversation(ROGUE, 51600, BASE_TS + 15.0)
    ts = BASE_TS + 15.1
    rogue.request(ts, ADDR_ROGUE, _request(FC_DISABLE_UNSOLICITED, seq=4))
    rogue.response(ts + 0.005, ADDR_ROGUE, _response(FC_RESPONSE, 0x0000, seq=4))
    rogue.request(ts + 0.3, ADDR_ROGUE, _request(FC_COLD_RESTART, seq=5))
    # A restarting device sets the Device Restart bit in its IIN.
    rogue.response(ts + 0.31, ADDR_ROGUE, _response(FC_RESPONSE, 0x0080, seq=5))
    rogue.request(ts + 0.6, ADDR_ROGUE, _request(FC_STOP_APPL, seq=6))
    rogue.response(ts + 0.61, ADDR_ROGUE, _response(FC_RESPONSE, 0x0080, seq=6))
    rogue.close(ts + 0.8)

    frames += rogue.frames
    frames.sort(key=lambda f: f[0])
    return frames


PROFILES = {
    "normal": profile_normal,
    "control": profile_control,
    "restart": profile_restart,
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
