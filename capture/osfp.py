"""Passive OS / stack fingerprinting from a TCP SYN — p0f's idea, honestly.

A machine states its operating system's defaults in the first packet of
every TCP connection, in the clear, no matter how encrypted the rest is: the
IP TTL it starts from, the TCP receive window it advertises, the maximum
segment size, whether it offers window scaling / SACK / timestamps, and the
ORDER it lists those options in. Those defaults differ between stacks enough
to tell Linux from Windows from a BSD or a network appliance — which is
exactly the kind of meaning this tool extracts from metadata rather than
payload.

TWO THINGS KEEP IT HONEST, the same discipline as the TLS client reading:

  COARSE, NOT EXACT. It reports a FAMILY (Linux/Android/macOS, Windows, a
  BSD/appliance), never a version — the signals cannot carry more than that
  without a large, staleness-prone signature database this tool will not
  vendor. A reading is "consistent with", joined to other evidence, never a
  verdict, and a shape it does not recognise is said to be unrecognised.

  THE TTL IS INFERRED, AND THE INFERENCE IS SHOWN. A packet's TTL has been
  decremented once per router it crossed, so the arriving value is below the
  sender's initial one. The initial TTL is recovered by rounding UP to the
  nearest common start (64/128/255); the difference is the hop distance,
  reported alongside so the reader sees the reasoning, not just a verdict.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional

__all__ = ["tcp_signature", "classify"]

#: The common initial TTLs stacks start from. A packet arrives at or below
#: one of these; the nearest at-or-above is the inferred start.
_INITIAL_TTLS = (64, 128, 255)

# TCP option kinds we read (RFC 793 / 1323 / 2018).
_OPT_EOL, _OPT_NOP, _OPT_MSS, _OPT_WSCALE, _OPT_SACKOK, _OPT_TS = 0, 1, 2, 3, 4, 8


def _infer_initial_ttl(ttl: int):
    for start in _INITIAL_TTLS:
        if ttl <= start:
            return start, start - ttl
    return None, None


def _parse_options(options: bytes):
    """(mss, wscale, sack_ok, timestamps, order-layout) from raw TCP options.

    `layout` is the sequence of option kinds in the order seen — a stack
    tell in itself (Linux and Windows list the same options differently)."""
    mss = wscale = None
    sack_ok = ts = False
    layout = []
    i = 0
    n = len(options)
    while i < n:
        kind = options[i]
        if kind == _OPT_EOL:
            break
        if kind == _OPT_NOP:
            layout.append("nop")
            i += 1
            continue
        if i + 1 >= n:
            break
        length = options[i + 1]
        if length < 2 or i + length > n:
            break
        body = options[i + 2:i + length]
        if kind == _OPT_MSS and len(body) == 2:
            mss = struct.unpack(">H", body)[0]
            layout.append("mss")
        elif kind == _OPT_WSCALE and len(body) == 1:
            wscale = body[0]
            layout.append("ws")
        elif kind == _OPT_SACKOK:
            sack_ok = True
            layout.append("sackok")
        elif kind == _OPT_TS:
            ts = True
            layout.append("ts")
        else:
            layout.append(str(kind))
        i += length
    return mss, wscale, sack_ok, ts, layout


def tcp_signature(ttl: int, window: int, options: bytes) -> Dict[str, Any]:
    """The readable fingerprint fields from a SYN / SYN-ACK."""
    initial, hops = _infer_initial_ttl(ttl)
    mss, wscale, sack_ok, ts, layout = _parse_options(options)
    return {
        "ttl": ttl,
        "initial_ttl": initial,
        "hops": hops,
        "window": window,
        "mss": mss,
        "wscale": wscale,
        "sack_ok": sack_ok,
        "timestamps": ts,
        "layout": layout,
    }


def classify(sig: Dict[str, Any]) -> Optional[str]:
    """A coarse OS family for a signature, or None when nothing is decisive.

    The initial TTL carries most of the signal and is the only thing trusted
    outright; window/options/timestamps refine the wording but never
    manufacture a verdict the TTL did not support.
    """
    initial = sig.get("initial_ttl")
    if initial is None:
        return None
    ts = sig.get("timestamps")
    if initial == 128:
        # Windows starts at 128 and, unlike modern unixes, historically omits
        # TCP timestamps by default.
        return "Windows"
    if initial == 64:
        # The big 64 family: Linux/Android, macOS, modern BSD. Timestamps on
        # is near-universal there; its absence is the one worth noting.
        if ts is False:
            return "a 64-TTL stack (Linux/macOS/BSD) with timestamps off"
        return "Linux / macOS / Android / BSD (TTL 64 family)"
    if initial == 255:
        return "a network appliance or BSD-derived stack (TTL 255)"
    return None
