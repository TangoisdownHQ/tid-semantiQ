"""Stdlib pcap / pcapng frame reader.

No third-party dependency, deliberately. scapy is heavyweight and slow for a
read-only path, and a dependency in a proprietary product is a dependency
that has to be defended; the headers we actually need are a few hundred lines
of struct unpacking. `capture/tshark.py` is the escape hatch for protocols
worth delegating to Wireshark's dissectors rather than reimplementing.

Yields `(frame_number, timestamp, linktype, frame_bytes)`. Frame numbers are
1-indexed to match how Wireshark counts, so a `Locus` built from them
produces a display filter that selects the same packet in the GUI.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator, Tuple

__all__ = ["read_frames", "read_stream", "LINKTYPE_ETHERNET", "LINKTYPE_RAW", "LINKTYPE_LINUX_SLL",
           "LINKTYPE_LINUX_SLL2", "LINKTYPE_NULL"]

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),      # little-endian, microseconds
    0xD4C3B2A1: (">", 1_000_000),      # big-endian, microseconds
    0xA1B23C4D: ("<", 1_000_000_000),  # little-endian, nanoseconds
    0x4D3CB2A1: (">", 1_000_000_000),  # big-endian, nanoseconds
}
_PCAPNG_SHB = 0x0A0D0D0A


def read_frames(path: Path | str) -> Iterator[Tuple[int, float, int, bytes]]:
    """Read either capture format, chosen by magic number.

    dumpcap and modern tshark write pcapng by default, so supporting only
    classic pcap would reject most captures the operator already has.
    """
    path = Path(path)
    with path.open("rb") as handle:
        head = handle.read(4)
        if len(head) < 4:
            return
        handle.seek(0)
        if struct.unpack("<I", head)[0] == _PCAPNG_SHB:
            yield from _read_pcapng(handle)
        else:
            yield from _read_pcap(handle)


def read_stream(handle) -> Iterator[Tuple[int, float, int, bytes]]:
    """Read frames from an already-open stream, which may be a pipe.

    Separate from `read_frames` for one reason: that function rewinds with
    `seek(0)` after sniffing the magic number, and a pipe cannot seek. Live
    capture arrives down a pipe from dumpcap, so the format has to be
    identified without consuming or rewinding — `peek` does that, and both
    readers below already consume their handle strictly forwards.

    The reader blocks waiting for the next frame, which is what a live
    capture requires: there is no end of file until the capture process
    exits.
    """
    head = handle.peek(4)[:4]
    if len(head) < 4:
        return
    if struct.unpack("<I", head)[0] == _PCAPNG_SHB:
        yield from _read_pcapng(handle)
    else:
        yield from _read_pcap(handle)


def _read_pcap(handle) -> Iterator[Tuple[int, float, int, bytes]]:
    header = handle.read(24)
    if len(header) < 24:
        return
    magic = struct.unpack("<I", header[:4])[0]
    if magic not in _PCAP_MAGICS:
        magic = struct.unpack(">I", header[:4])[0]
    if magic not in _PCAP_MAGICS:
        raise ValueError("not a pcap or pcapng file")
    endian, ticks_per_s = _PCAP_MAGICS[magic]
    linktype = struct.unpack(endian + "I", header[20:24])[0]

    frame = 0
    while True:
        record = handle.read(16)
        if len(record) < 16:
            return
        ts_sec, ts_frac, caplen, _origlen = struct.unpack(endian + "IIII", record)
        data = handle.read(caplen)
        if len(data) < caplen:
            return
        frame += 1
        yield frame, ts_sec + ts_frac / ticks_per_s, linktype, data


def _read_pcapng(handle) -> Iterator[Tuple[int, float, int, bytes]]:
    endian = "<"
    # Per-interface link type and timestamp resolution. Both are per-IDB, and
    # getting tsresol wrong silently scales every interval — which would
    # corrupt the one thing this tool measures most carefully.
    interfaces: list[tuple[int, int]] = []
    frame = 0

    while True:
        head = handle.read(8)
        if len(head) < 8:
            return
        block_type = struct.unpack(endian + "I", head[:4])[0]
        if block_type == _PCAPNG_SHB:
            # Byte-order magic lives in the SHB body; re-read with it known.
            body_len = struct.unpack(endian + "I", head[4:8])[0]
            rest = handle.read(body_len - 8)
            if len(rest) < 4:
                return
            if struct.unpack("<I", rest[:4])[0] != 0x1A2B3C4D:
                endian = ">"
            interfaces = []
            continue

        block_len = struct.unpack(endian + "I", head[4:8])[0]
        if block_len < 12:
            return
        body = handle.read(block_len - 12)
        trailer = handle.read(4)
        if len(trailer) < 4:
            return

        if block_type == 0x00000001:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            interfaces.append((linktype, _tsresol(body[8:], endian)))

        elif block_type == 0x00000006:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, caplen, _origlen = struct.unpack(
                endian + "IIIII", body[:20]
            )
            linktype, divisor = (
                interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1_000_000)
            )
            ts = ((ts_hi << 32) | ts_lo) / divisor
            frame += 1
            yield frame, ts, linktype, body[20:20 + caplen]

        elif block_type == 0x00000003:  # Simple Packet Block — no timestamp
            frame += 1
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield frame, 0.0, linktype, body[4:]


def _tsresol(options: bytes, endian: str) -> int:
    """Timestamp divisor from the IDB's if_tsresol option (code 9).

    Default is microseconds. A capture written with nanosecond resolution and
    read as microseconds reports every interval 1000x too long, so this is
    worth parsing rather than assuming.
    """
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset:offset + 4])
        value = options[offset + 4:offset + 4 + length]
        if code == 0:
            break
        if code == 9 and value:
            raw = value[0]
            if raw & 0x80:
                return 2 ** (raw & 0x7F)
            return 10 ** raw
        offset += 4 + length + (-length % 4)
    return 1_000_000
