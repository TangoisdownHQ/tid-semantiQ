#!/usr/bin/env python3
"""Synthesise a Modbus/TCP capture.

Modbus is cleartext, so unlike the TLS fixture this needs no relay and no
keys — the bytes are assembled directly. It is also a good test of the
"adding a domain is cheap" claim, because Modbus/TCP rides IP and Wireshark
already dissects it.

Wire format, for reference while reading the builders below:

    MBAP header   trans_id(2) prot_id(2)=0 length(2) unit_id(1)
                  `length` counts the bytes AFTER it, i.e. unit_id + PDU
    PDU           func_code(1) + function-specific data
    exception     func_code|0x80 (1) + exception_code(1)

One TCP connection carries many transactions, which is how real Modbus
masters work — so this also exercises the `txn` pairing that `tcp.stream`
cannot do.

    python3 tools/make_modbus_pcap.py out/modbus.pcap --profile normal
    python3 tools/make_modbus_pcap.py out/modbus.pcap --profile write
    python3 tools/make_modbus_pcap.py out/modbus.pcap --profile scan
"""

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path
from typing import Dict, List, Tuple

MASTER = "10.20.0.10"
PLC = "10.20.0.50"
ROGUE = "10.20.0.77"
MODBUS_PORT = 502
BASE_TS = 1_790_000_000.0

# function codes
FC_READ_COILS = 1
FC_READ_HOLDING = 3
FC_READ_INPUT = 4
FC_WRITE_COIL = 5
FC_WRITE_REGISTER = 6
FC_WRITE_MULTIPLE = 16

Frame = Tuple[float, bytes]


# --------------------------------------------------------------------------
# Modbus PDUs
# --------------------------------------------------------------------------


def _mbap(trans_id: int, unit: int, pdu: bytes) -> bytes:
    # length counts unit_id plus the PDU.
    return struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, unit) + pdu


def read_request(trans_id: int, unit: int, fc: int, start: int, count: int) -> bytes:
    return _mbap(trans_id, unit, struct.pack(">BHH", fc, start, count))


def read_response(trans_id: int, unit: int, fc: int, values: List[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    return _mbap(trans_id, unit, struct.pack(">BB", fc, len(body)) + body)


def write_register_request(trans_id: int, unit: int, addr: int, value: int) -> bytes:
    return _mbap(trans_id, unit, struct.pack(">BHH", FC_WRITE_REGISTER, addr, value))


def write_register_response(trans_id: int, unit: int, addr: int, value: int) -> bytes:
    # A successful single-register write echoes the request.
    return write_register_request(trans_id, unit, addr, value)


def write_multiple_request(
    trans_id: int, unit: int, addr: int, values: List[int]
) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    return _mbap(trans_id, unit, struct.pack(
        ">BHHB", FC_WRITE_MULTIPLE, addr, len(values), len(body)
    ) + body)


def write_multiple_response(
    trans_id: int, unit: int, addr: int, count: int
) -> bytes:
    return _mbap(trans_id, unit, struct.pack(">BHH", FC_WRITE_MULTIPLE, addr, count))


def exception_response(trans_id: int, unit: int, fc: int, code: int) -> bytes:
    return _mbap(trans_id, unit, struct.pack(">BB", fc | 0x80, code))


# --------------------------------------------------------------------------
# framing
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
    """One TCP connection between a master and a PLC, with correct sequencing.

    Sequence numbers must be right or Wireshark will not reassemble, and
    without reassembly it cannot pair transactions — which is the thing this
    fixture exists to exercise.
    """

    def __init__(self, client: str, port: int, start: float):
        self.client = client
        self.port = port
        self.frames: List[Frame] = []
        self.c_seq = 1000
        self.s_seq = 5000
        self._open(start)

    def _emit(self, ts: float, from_client: bool, flags: int,
              payload: bytes = b"") -> None:
        if from_client:
            packet = _tcp(self.port, MODBUS_PORT, self.c_seq, self.s_seq,
                          flags, payload)
            self.frames.append((ts, _eth(_ipv4(self.client, PLC, packet))))
            self.c_seq += len(payload)
        else:
            packet = _tcp(MODBUS_PORT, self.port, self.s_seq, self.c_seq,
                          flags, payload)
            self.frames.append((ts, _eth(_ipv4(PLC, self.client, packet))))
            self.s_seq += len(payload)

    def _open(self, ts: float) -> None:
        self._emit(ts, True, 0x02)                 # SYN
        self.c_seq += 1
        self._emit(ts + 0.0005, False, 0x12)       # SYN-ACK
        self.s_seq += 1
        self._emit(ts + 0.001, True, 0x10)         # ACK

    def exchange(self, ts: float, request: bytes, response: bytes,
                 latency: float = 0.004) -> None:
        self._emit(ts, True, 0x18, request)
        self._emit(ts + latency, False, 0x18, response)

    def close(self, ts: float) -> None:
        self._emit(ts, True, 0x11)
        self._emit(ts + 0.001, False, 0x11)


# --------------------------------------------------------------------------
# profiles
# --------------------------------------------------------------------------


def profile_normal(rng: random.Random) -> List[Frame]:
    """A master polling one PLC on a steady 1s scan cycle. Reads only.

    This is the baseline a deployment would build its history from, and the
    shape that makes Modbus the easiest domain for the timing primitives:
    periodic by design, so deviation is meaningful.
    """
    conv = Conversation(MASTER, 49200, BASE_TS)
    ts = BASE_TS + 0.01
    trans = 1
    for cycle in range(60):
        # Scan cycle: read holding registers, then input registers.
        conv.exchange(
            ts, read_request(trans, 1, FC_READ_HOLDING, 0, 10),
            read_response(trans, 1, FC_READ_HOLDING,
                          [100 + cycle] * 10),
            latency=0.004 + rng.uniform(-0.0005, 0.0005),
        )
        trans += 1
        conv.exchange(
            ts + 0.05, read_request(trans, 1, FC_READ_INPUT, 0, 4),
            read_response(trans, 1, FC_READ_INPUT, [7, 8, 9, 10]),
            latency=0.004 + rng.uniform(-0.0005, 0.0005),
        )
        trans += 1
        ts += 1.0 + rng.uniform(-0.004, 0.004)     # real scan jitter
    conv.close(ts)
    return conv.frames


def profile_write(rng: random.Random) -> List[Frame]:
    """Normal polling, then an unexpected WRITE from a different host.

    The ICS finding that matters: a host that has never issued a command
    suddenly changing a register. ATT&CK for ICS T0855 (Unauthorized Command
    Message) / T0836 (Modify Parameter).
    """
    frames = profile_normal(rng)

    rogue = Conversation(ROGUE, 51000, BASE_TS + 31.0)
    ts = BASE_TS + 31.1
    rogue.exchange(
        ts, write_register_request(900, 1, 40001, 0),
        write_register_response(900, 1, 40001, 0),
    )
    rogue.exchange(
        ts + 0.2,
        write_multiple_request(901, 1, 40010, [0, 0, 0, 1]),
        write_multiple_response(901, 1, 40010, 4),
    )
    rogue.exchange(
        ts + 0.4, write_register_request(902, 1, 40002, 65535),
        write_register_response(902, 1, 40002, 65535),
    )
    rogue.close(ts + 0.6)

    frames += rogue.frames
    frames.sort(key=lambda f: f[0])
    return frames


def profile_scan(rng: random.Random) -> List[Frame]:
    """Normal polling, plus unit-id and function-code enumeration.

    A scanner walking unit ids collects exception responses from the units
    that do not exist, which is the signature. ATT&CK for ICS T0842 /
    T0846 (Remote System Discovery).
    """
    frames = profile_normal(rng)

    scanner = Conversation(ROGUE, 52000, BASE_TS + 20.0)
    ts = BASE_TS + 20.1
    trans = 2000

    # Walk unit ids 1..24; only unit 1 answers.
    for unit in range(1, 25):
        if unit == 1:
            response = read_response(trans, unit, FC_READ_HOLDING, [1, 2])
        else:
            # 0x0B = gateway target device failed to respond
            response = exception_response(trans, unit, FC_READ_HOLDING, 0x0B)
        scanner.exchange(
            ts, read_request(trans, unit, FC_READ_HOLDING, 0, 2), response,
            latency=0.002,
        )
        trans += 1
        ts += 0.05

    # Then walk function codes against the unit that answered.
    for fc in (1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 20, 21, 43):
        if fc in (FC_READ_COILS, FC_READ_HOLDING, FC_READ_INPUT):
            response = read_response(trans, 1, fc, [0])
        else:
            # 0x01 = illegal function
            response = exception_response(trans, 1, fc, 0x01)
        scanner.exchange(
            ts, read_request(trans, 1, fc, 0, 1), response, latency=0.002,
        )
        trans += 1
        ts += 0.05

    scanner.close(ts)
    frames += scanner.frames
    frames.sort(key=lambda f: f[0])
    return frames


PROFILES = {
    "normal": profile_normal,
    "write": profile_write,
    "scan": profile_scan,
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
