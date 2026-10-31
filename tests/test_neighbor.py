"""ARP / NDP neighbour resolution — the LAN's IP<->MAC table.

ARP is not IP, so it was dropped before this existed; the parser has to
reach its bytes through the same VLAN unwrapping the IP path uses. The table
then has one job beyond naming: catch an IP claimed by two MACs (ARP cache
poisoning) while staying honest that a DHCP reassignment looks identical.
The end-to-end tests prove ARP pairings override the weaker inferred MAC and
reach both device naming and the conflicts section.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.base import group_into_series
from capture.decode import arp_info, ndp_pairings
from capture.neighbor import NeighborTable
from capture.pcap import PcapSource
from capture.pcapfile import LINKTYPE_ETHERNET
from out.narrate import narrate


# --------------------------------------------------------------------------
# frame builders
# --------------------------------------------------------------------------


def _arp_frame(opcode, sender_ip, sender_mac, target_ip, target_mac,
               vlan=None):
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, opcode)
    arp += bytes.fromhex(sender_mac.replace(":", ""))
    arp += bytes(int(o) for o in sender_ip.split("."))
    arp += bytes.fromhex(target_mac.replace(":", ""))
    arp += bytes(int(o) for o in target_ip.split("."))
    eth = b"\xff\xff\xff\xff\xff\xff" + bytes.fromhex(sender_mac.replace(":", ""))
    if vlan is not None:
        eth += struct.pack(">HH", 0x8100, vlan) + b"\x08\x06"
    else:
        eth += b"\x08\x06"
    return eth + arp


def _ndp_na_frame(src_ipv6, target_ipv6, target_mac):
    # ICMPv6 Neighbor Advertisement (136) with a target link-layer option (2).
    icmp = bytes([136, 0]) + b"\x00\x00"           # type, code, checksum
    icmp += b"\x60\x00\x00\x00"                    # flags
    import ipaddress
    icmp += ipaddress.IPv6Address(target_ipv6).packed
    icmp += bytes([2, 1]) + bytes.fromhex(target_mac.replace(":", ""))  # opt
    # IPv6 header: version/class/label, payload len, next=58 (ICMPv6), hop
    ip6 = b"\x60\x00\x00\x00" + struct.pack(">H", len(icmp)) + bytes([58, 255])
    ip6 += ipaddress.IPv6Address(src_ipv6).packed
    ip6 += ipaddress.IPv6Address(target_ipv6).packed
    return b"\xff\xff\xff\xff\xff\xff\xaa\xaa\xaa\xaa\xaa\xaa\x86\xdd" + ip6 + icmp


def _write_pcap(path, frames):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, LINKTYPE_ETHERNET))
        for i, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                     len(frame), len(frame)))
            handle.write(frame)


# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------


def test_arp_reply_parses_both_pairings():
    frame = _arp_frame(2, "10.0.0.1", "aa:bb:cc:11:22:33",
                       "10.0.0.50", "de:ad:be:ef:00:01")
    info = arp_info(LINKTYPE_ETHERNET, frame)
    assert info.opcode == "reply"
    assert info.sender_ip == "10.0.0.1" and info.sender_mac == "aa:bb:cc:11:22:33"
    assert info.target_ip == "10.0.0.50"


def test_arp_through_a_vlan_tag():
    frame = _arp_frame(2, "10.0.0.1", "aa:bb:cc:11:22:33",
                       "10.0.0.2", "00:00:00:00:00:00", vlan=100)
    info = arp_info(LINKTYPE_ETHERNET, frame)
    assert info is not None and info.sender_ip == "10.0.0.1"


def test_non_arp_and_non_ethernet_return_none():
    from capture.pcapfile import LINKTYPE_RAW
    ip_frame = b"\xff" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 30
    assert arp_info(LINKTYPE_ETHERNET, ip_frame) is None
    frame = _arp_frame(1, "10.0.0.1", "aa:bb:cc:11:22:33", "10.0.0.2",
                       "00:00:00:00:00:00")
    assert arp_info(LINKTYPE_RAW, frame) is None


def test_ndp_advertisement_pairs_target_with_its_mac():
    frame = _ndp_na_frame("fe80::1", "fe80::50", "de:ad:be:ef:00:50")
    # extract the ICMPv6 payload the way pcap does: strip 14-byte eth + 40 ip6
    icmp = frame[14 + 40:]
    from capture.decode import PROTO_ICMPV6
    pairs = ndp_pairings(PROTO_ICMPV6, icmp, "fe80::1")
    assert ("fe80::50", "de:ad:be:ef:00:50") in pairs


# --------------------------------------------------------------------------
# the table
# --------------------------------------------------------------------------


def test_pairings_pick_the_most_asserted_mac():
    t = NeighborTable()
    for _ in range(5):
        t.observe("10.0.0.1", "aa:aa:aa:aa:aa:aa", ts=1.0)
    t.observe("10.0.0.1", "bb:bb:bb:bb:bb:bb", ts=2.0)   # a brief spoof
    assert t.pairings()["10.0.0.1"] == "aa:aa:aa:aa:aa:aa"


def test_conflict_is_detected_and_a_lone_pairing_is_not():
    t = NeighborTable()
    t.observe("10.0.0.1", "aa:aa:aa:aa:aa:aa", ts=1.0)
    t.observe("10.0.0.1", "bb:bb:bb:bb:bb:bb", ts=2.0)
    t.observe("10.0.0.9", "cc:cc:cc:cc:cc:cc", ts=1.0)
    conflicts = t.conflicts()
    assert len(conflicts) == 1
    assert conflicts[0].ip == "10.0.0.1"
    assert {c[0] for c in conflicts[0].claims} == {
        "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}


def test_zero_mac_is_ignored():
    t = NeighborTable()
    t.observe("10.0.0.1", "00:00:00:00:00:00")
    assert t.pairings() == {}


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------


def test_arp_pairings_reach_naming_and_override_inferred():
    """An ARP reply naming 10.0.0.1's MAC must win over any MAC inferred from
    that host's own IP packets, and reach device naming via host_macs."""
    frames = [
        _arp_frame(2, "10.0.0.1", "b8:27:eb:aa:bb:cc",
                   "10.0.0.50", "de:ad:be:ef:00:01"),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.pcap"
        _write_pcap(path, frames)
        source = PcapSource(path)
        list(source.observations())
    assert source.stats["host_macs"]["10.0.0.1"] == "b8:27:eb:aa:bb:cc"
    assert "10.0.0.1" in source.stats["neighbors"]["pairings"]


def test_arp_conflict_reaches_the_report():
    frames = [
        _arp_frame(2, "10.0.0.1", "aa:aa:aa:aa:aa:aa", "10.0.0.50",
                   "de:ad:be:ef:00:01"),
        _arp_frame(2, "10.0.0.1", "bb:bb:bb:bb:bb:bb", "10.0.0.50",
                   "de:ad:be:ef:00:01"),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.pcap"
        _write_pcap(path, frames)
        source = PcapSource(path)
        series = list(source.observations())
    text = narrate(series, [], stats=source.stats, source_name="t.pcap")
    assert "ADDRESS / HARDWARE CONFLICTS" in text
    assert "aa:aa:aa:aa:aa:aa" in text and "bb:bb:bb:bb:bb:bb" in text
    assert "cache poisoning" in text
    # honest: the innocent causes are named
    assert "DHCP reassignment" in text or "router-redundancy" in text


def test_glossary_covers_arp():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "ARP cache poisoning claimed the gateway's hardware address")}
    assert "ARP / NDP (neighbour resolution)" in found


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
