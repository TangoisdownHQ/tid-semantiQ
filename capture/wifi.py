"""Wi-Fi management-frame intelligence — readable even on a WPA network.

A capture of a WPA/WPA3 network hands over almost no readable payload: the
data frames are encrypted. But the MANAGEMENT frames — the ones that set a
link up and tear it down — are sent in the clear, and they are where the
meaning is on a protected network:

  BEACONS / PROBE RESPONSES name the access points present and the SSIDs
  they serve — the networks in the air, and which are hidden.

  PROBE REQUESTS are clients asking "is network X here?" — a device leaks the
  names of networks it has joined before, which fingerprints the device and
  its history. A broadcast probe (empty SSID) is a client asking for any.

  DEAUTHENTICATIONS / DISASSOCIATIONS kick a client off. A few are normal
  (a roam, a shutdown); a FLOOD of them is the classic Wi-Fi denial-of-
  service and the first move of an evil-twin or handshake-capture attack.

This reads only those unencrypted management frames; it decrypts nothing.
The honesty rule is the usual one: a deauth count is reported with the note
that normal disconnects deauth too, so a high count is a lead to confirm,
not a verdict. Kept a capture-level fact (like the neighbour table), not a
scored channel — an access point in the air is not a conversation with a
cadence.
"""

from __future__ import annotations

import struct
from collections import Counter
from typing import Any, Dict, Optional

__all__ = ["WifiMonitor"]

# 802.11 management-frame subtypes (type 0).
_ASSOC_REQ, _PROBE_REQ, _BEACON = 0x0, 0x4, 0x8
_PROBE_RESP, _DISASSOC, _AUTH, _DEAUTH = 0x5, 0xA, 0xB, 0xC


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ssid_from_tags(body: bytes) -> Optional[str]:
    """The SSID (tag 0) from a tagged-parameter block, or None.

    Returns "" for a present-but-empty SSID — a hidden network in a beacon,
    a wildcard in a probe request — which is itself information, distinct
    from no SSID tag at all.
    """
    i = 0
    n = len(body)
    while i + 2 <= n:
        tag, length = body[i], body[i + 1]
        if i + 2 + length > n:
            break
        if tag == 0:   # SSID
            raw = body[i + 2:i + 2 + length]
            return raw.decode("utf-8", "replace")
        i += 2 + length
    return None


class WifiMonitor:
    def __init__(self) -> None:
        self.aps: Dict[str, Dict[str, Any]] = {}      # bssid -> {ssid, beacons}
        self.probes: Dict[str, Counter] = {}          # client -> Counter(ssid)
        self.deauths: Counter = Counter()             # (src, dst) -> count
        self.frames = 0

    def observe(self, dot11: bytes) -> None:
        """Feed one raw 802.11 frame. Non-management frames are ignored."""
        if len(dot11) < 2:
            return
        fc0 = dot11[0]
        ftype = (fc0 >> 2) & 0x03
        subtype = (fc0 >> 4) & 0x0F
        if ftype != 0:                    # 0 = management
            return
        self.frames += 1
        if len(dot11) < 24:               # management header: FC..SeqCtl
            return
        da = _mac(dot11[4:10])            # addr1 destination
        sa = _mac(dot11[10:16])           # addr2 source
        bssid = _mac(dot11[16:22])        # addr3
        body = dot11[24:]

        if subtype in (_BEACON, _PROBE_RESP):
            # body: timestamp(8) interval(2) capability(2) then tagged params
            ssid = _ssid_from_tags(body[12:]) if len(body) > 12 else None
            ap = self.aps.setdefault(bssid, {"ssid": None, "beacons": 0})
            ap["beacons"] += 1
            if ssid:                      # non-empty wins over hidden/None
                ap["ssid"] = ssid
            elif ssid == "" and ap["ssid"] is None:
                ap["ssid"] = "<hidden>"
        elif subtype == _PROBE_REQ:
            ssid = _ssid_from_tags(body)
            label = ssid if ssid else "<broadcast>"
            self.probes.setdefault(sa, Counter())[label] += 1
        elif subtype in (_DEAUTH, _DISASSOC):
            self.deauths[(sa, da)] += 1

    def report(self) -> Dict[str, Any]:
        """Capture-level wireless summary; empty when no management frames
        were seen, so a non-Wi-Fi capture adds no section."""
        if not (self.aps or self.probes or self.deauths):
            return {}
        return {
            "aps": {b: dict(v) for b, v in self.aps.items()},
            "probes": {c: dict(ctr) for c, ctr in self.probes.items()},
            "deauths": {"total": sum(self.deauths.values()),
                        "pairs": self.deauths.most_common(8)},
            "frames": self.frames,
        }
