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
from typing import Any, Dict, Optional, Tuple

__all__ = ["WifiMonitor"]

# 802.11 management-frame subtypes (type 0).
_ASSOC_REQ, _PROBE_REQ, _BEACON = 0x0, 0x4, 0x8
_PROBE_RESP, _DISASSOC, _AUTH, _DEAUTH = 0x5, 0xA, 0xB, 0xC


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _parse_eapol_key(body: bytes):
    """(message 1-4 or None, has_pmkid) from an EAPOL-Key frame body.

    The 4-way handshake is told apart by the Key Information field:
      M1 = ACK, no MIC        (AP -> STA, carries the ANonce)
      M2 = MIC, no ACK        (STA -> AP, carries the SNonce and the MIC)
      M3 = MIC + ACK + Install + Secure
      M4 = MIC, Secure, no ACK
    Capturing a nonce-bearing message (M1/M3) and a MIC-bearing one (M2/M4)
    for a pair is the material an offline cracker needs. PMKID, when present,
    rides M1's key-data as an RSN KDE and is crackable with no client at all.

    Bounds-checked throughout: this is fed hostile bytes by the fuzz suite.
    """
    # EAPOL header: version(1) type(1) length(2); type 3 = Key.
    if len(body) < 4 or body[1] != 3:
        return None, False
    key = body[4:]
    if len(key) < 3:
        return None, False
    info = (key[1] << 8) | key[2]          # Key Information, big-endian
    install = bool(info & 0x0040)
    ack = bool(info & 0x0080)
    mic = bool(info & 0x0100)
    secure = bool(info & 0x0200)
    if ack and not mic:
        msg = 1
    elif mic and ack and install and secure:
        msg = 3
    elif mic and not ack and secure:
        msg = 4
    elif mic and not ack:
        msg = 2
    else:
        return None, False

    has_pmkid = False
    if msg == 1:
        # Fixed EAPOL-Key fields before Key Data: descriptor(1) info(2)
        # keylen(2) replay(8) nonce(32) iv(16) rsc(8) reserved(8) mic(16)
        # datalen(2) = 95 bytes; Key Data follows.
        if len(key) >= 95:
            data_len = (key[93] << 8) | key[94]
            data = key[95:95 + data_len]
            has_pmkid = _has_pmkid(data)
    return msg, has_pmkid


def _has_pmkid(key_data: bytes) -> bool:
    """A non-zero PMKID KDE (tag 0xDD, OUI 00-0F-AC, type 4) in Key Data."""
    i = 0
    n = len(key_data)
    while i + 2 <= n:
        if key_data[i] != 0xDD:
            i += 1
            continue
        length = key_data[i + 1]
        kde = key_data[i + 2:i + 2 + length]
        if (len(kde) >= 20 and kde[:3] == b"\x00\x0f\xac" and kde[3] == 4
                and kde[4:20] != b"\x00" * 16):
            return True
        i += 2 + length
    return False


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
        # (bssid, client) -> set of 4-way-handshake messages seen (1..4).
        self.handshakes: Dict[Tuple[str, str], set] = {}
        # (bssid, client) -> True once a non-zero PMKID was seen in M1.
        self.pmkids: Dict[Tuple[str, str], bool] = {}
        self.frames = 0

    def observe(self, dot11: bytes) -> None:
        """Feed one raw 802.11 frame. Management frames and the EAPOL data
        frames of a WPA handshake are read; everything else is ignored."""
        if len(dot11) < 2:
            return
        fc0, fc1 = dot11[0], dot11[1]
        ftype = (fc0 >> 2) & 0x03
        subtype = (fc0 >> 4) & 0x0F

        if ftype == 2:                    # data: only EAPOL interests us
            self._data_frame(fc0, fc1, subtype, dot11)
            return
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

    def _data_frame(self, fc0, fc1, subtype, dot11) -> None:
        """A WPA 4-way-handshake message rides an (unencrypted) EAPOL data
        frame. Pull out which message it is, and any PMKID, for offline-crack
        exposure reporting."""
        if fc1 & 0x40:                    # Protected: not a handshake frame
            return
        header = 24
        if (fc1 & 0x01) and (fc1 & 0x02):  # 4-address
            header += 6
        if subtype & 0x08:                 # QoS data
            header += 2
            if fc1 & 0x80:                 # HT control
                header += 4
        # LLC/SNAP: AA AA 03 00 00 00 <ethertype>. EAPOL is 0x888E.
        if len(dot11) < header + 8 + 4:
            return
        if dot11[header:header + 6] != b"\xaa\xaa\x03\x00\x00\x00":
            return
        if dot11[header + 6:header + 8] != b"\x88\x8e":
            return
        addr1 = _mac(dot11[4:10])
        addr2 = _mac(dot11[10:16])
        bssid = _mac(dot11[16:22])
        client = addr1 if addr2 == bssid else addr2
        key = (bssid, client)

        msg, has_pmkid = _parse_eapol_key(dot11[header + 8:])
        if msg is None:
            return
        self.frames += 1
        self.handshakes.setdefault(key, set()).add(msg)
        if has_pmkid:
            self.pmkids[key] = True

    def report(self) -> Dict[str, Any]:
        """Capture-level wireless summary; empty when no management frames
        were seen, so a non-Wi-Fi capture adds no section."""
        if not (self.aps or self.probes or self.deauths
                or self.handshakes or self.pmkids):
            return {}
        # A pair is "crackable" once both a nonce-bearing message (M1 or M3)
        # and a MIC-bearing one (M2 or M4) have been captured.
        handshakes = []
        for (bssid, client), msgs in self.handshakes.items():
            crackable = bool(msgs & {1, 3}) and bool(msgs & {2, 4})
            handshakes.append({
                "bssid": bssid, "client": client,
                "messages": sorted(msgs),
                "crackable": crackable,
                "pmkid": self.pmkids.get((bssid, client), False),
            })
        return {
            "aps": {b: dict(v) for b, v in self.aps.items()},
            "probes": {c: dict(ctr) for c, ctr in self.probes.items()},
            "deauths": {"total": sum(self.deauths.values()),
                        "pairs": self.deauths.most_common(8)},
            "handshakes": handshakes,
            "frames": self.frames,
        }
