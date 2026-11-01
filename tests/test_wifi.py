"""802.11 / radiotap link-layer decoding — reading Wi-Fi captures.

Monitor-mode captures arrive as radiotap-wrapped 802.11 frames, which the
decoder dropped whole before this existed. The parser has to walk a
variable-length 802.11 header (4-address, QoS, HT-control variants all move
the payload) to the LLC/SNAP shim and then the IP — and it must refuse what
it cannot read honestly: management/control frames carry no IP, and a
Protected (WPA) data frame's payload is ciphertext with no LLC, so both yield
nothing rather than a mis-parse. These build the frames by hand and drive
them through the real decode path.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.decode import decode_ip, decode_udp
from capture.pcapfile import (
    LINKTYPE_IEEE802_11,
    LINKTYPE_IEEE802_11_RADIOTAP,
)

_LLC_IP = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"      # SNAP, ethertype IPv4


def _ipv4_udp(src="10.0.0.5", dst="10.0.0.9", sport=5000, dport=53,
              payload=b"hello") -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
                       bytes(int(o) for o in src.split(".")),
                       bytes(int(o) for o in dst.split("."))) + udp


def _dot11_data(ip: bytes, fc1=0x00, qos=False, four_addr=False,
                ht=False, protected=False) -> bytes:
    """A minimal 802.11 data frame carrying `ip` under an LLC/SNAP shim."""
    fc0 = 0x08                       # type=2 (data), subtype=0
    if qos:
        fc0 = 0x88                   # subtype 8 = QoS data
    if protected:
        fc1 |= 0x40
    if four_addr:
        fc1 |= 0x03                  # ToDS + FromDS
    if ht:
        fc1 |= 0x80                  # Order -> HT control (only with QoS)
    frame = bytes([fc0, fc1])
    frame += b"\x00\x00"             # duration
    frame += b"\x11" * 6 * 3         # addr1, addr2, addr3
    frame += b"\x00\x00"             # sequence control
    if four_addr:
        frame += b"\x22" * 6         # addr4
    if qos:
        frame += b"\x00\x00"         # QoS control
        if ht:
            frame += b"\x00\x00\x00\x00"   # HT control
    body = _LLC_IP + ip if not protected else b"\xde\xad" * 20
    return frame + body


def _radiotap(dot11: bytes, rt_len=8) -> bytes:
    header = struct.pack("<BBH", 0, 0, rt_len) + b"\x00" * (rt_len - 4)
    return header + dot11


# --------------------------------------------------------------------------
# the happy paths
# --------------------------------------------------------------------------


def test_radiotap_wrapped_data_frame_decodes_to_ip():
    frame = _radiotap(_dot11_data(_ipv4_udp(dport=53)))
    pkt = decode_ip(LINKTYPE_IEEE802_11_RADIOTAP, frame)
    assert pkt is not None and pkt.src == "10.0.0.5" and pkt.dst == "10.0.0.9"
    seg = decode_udp(pkt.payload)
    assert seg is not None and seg.dport == 53


def test_bare_802_11_without_radiotap():
    frame = _dot11_data(_ipv4_udp())
    pkt = decode_ip(LINKTYPE_IEEE802_11, frame)
    assert pkt is not None and pkt.src == "10.0.0.5"


def test_qos_four_address_and_ht_header_lengths():
    """Each variant moves the payload; all must still reach the IP."""
    for kw in ({"qos": True},
               {"four_addr": True},
               {"qos": True, "four_addr": True},
               {"qos": True, "ht": True}):
        frame = _radiotap(_dot11_data(_ipv4_udp(dport=443), **kw))
        pkt = decode_ip(LINKTYPE_IEEE802_11_RADIOTAP, frame)
        assert pkt is not None and pkt.dst == "10.0.0.9", kw


# --------------------------------------------------------------------------
# the honest refusals
# --------------------------------------------------------------------------


def test_protected_frame_yields_no_ip():
    """A WPA data frame is ciphertext with no LLC — like an encrypted TLS
    record, it must produce nothing, not a mis-parse."""
    frame = _radiotap(_dot11_data(_ipv4_udp(), protected=True))
    assert decode_ip(LINKTYPE_IEEE802_11_RADIOTAP, frame) is None


def test_management_and_control_frames_carry_no_ip():
    # a beacon (management, type 0, subtype 8) wrapped in radiotap
    beacon = bytes([0x80, 0x00]) + b"\x00" * 30
    assert decode_ip(LINKTYPE_IEEE802_11_RADIOTAP, _radiotap(beacon)) is None
    # an ACK (control, type 1)
    ack = bytes([0xD4, 0x00]) + b"\x00" * 10
    assert decode_ip(LINKTYPE_IEEE802_11, ack) is None


def test_truncated_radiotap_and_frames_do_not_crash():
    assert decode_ip(LINKTYPE_IEEE802_11_RADIOTAP, b"\x00\x00") is None
    # radiotap claims a length longer than the frame
    bad = struct.pack("<BBH", 0, 0, 200) + b"\x00" * 10
    assert decode_ip(LINKTYPE_IEEE802_11_RADIOTAP, bad) is None
    assert decode_ip(LINKTYPE_IEEE802_11, b"\x08") is None


def test_non_llc_payload_is_not_mistaken_for_ip():
    # a data frame whose body is not an LLC/SNAP IP shim
    frame = _dot11_data(_ipv4_udp())
    frame = frame[: -len(_LLC_IP + _ipv4_udp())] + b"\x00" * 20
    assert decode_ip(LINKTYPE_IEEE802_11, frame) is None


# --------------------------------------------------------------------------
# end to end through the pcap reader
# --------------------------------------------------------------------------


def test_monitor_mode_capture_reads_through_pcapsource():
    import tempfile
    from capture.base import group_into_series
    from capture.pcap import PcapSource

    frames = [_radiotap(_dot11_data(_ipv4_udp(dport=53, payload=b"q" + bytes(i))))
              for i in range(3)]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "wifi.pcap"
        with open(path, "wb") as handle:
            # pcap global header with the radiotap linktype
            handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                     65535, LINKTYPE_IEEE802_11_RADIOTAP))
            for i, frame in enumerate(frames):
                handle.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                         len(frame), len(frame)))
                handle.write(frame)
        source = PcapSource(path)
        obs = list(source.observations())
    assert source.stats["decoded"] == 3, source.stats
    assert source.stats["udp"] == 3


def test_glossary_covers_wifi():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "a monitor mode capture with a radiotap header, 802.11 beacons")}
    assert "802.11 / monitor mode / radiotap" in found


# --------------------------------------------------------------------------
# management-frame intelligence (beacons, probes, deauth)
# --------------------------------------------------------------------------


def _ssid_tag(ssid: str) -> bytes:
    raw = ssid.encode()
    return bytes([0, len(raw)]) + raw


def _mgmt(subtype: int, sa: str, da: str, bssid: str, body: bytes) -> bytes:
    fc0 = (subtype << 4) | (0 << 2)          # type 0 = management
    frame = bytes([fc0, 0x00]) + b"\x00\x00"  # FC + duration
    for mac in (da, sa, bssid):
        frame += bytes.fromhex(mac.replace(":", ""))
    frame += b"\x00\x00"                      # sequence control
    return frame + body


def _beacon(bssid: str, ssid: str) -> bytes:
    body = b"\x00" * 8 + b"\x64\x00" + b"\x01\x04"   # timestamp, interval, cap
    body += _ssid_tag(ssid)
    return _mgmt(0x8, bssid, "ff:ff:ff:ff:ff:ff", bssid, body)


def _probe_req(client: str, ssid: str) -> bytes:
    return _mgmt(0x4, client, "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff",
                 _ssid_tag(ssid))


def _deauth(src: str, dst: str) -> bytes:
    return _mgmt(0xC, src, dst, src, b"\x07\x00")     # reason 7


def test_wifi_monitor_reads_beacons_probes_deauths():
    from capture.wifi import WifiMonitor
    mon = WifiMonitor()
    for _ in range(5):
        mon.observe(_beacon("aa:bb:cc:00:00:01", "CorpWiFi"))
    mon.observe(_beacon("aa:bb:cc:00:00:02", ""))          # hidden SSID
    mon.observe(_probe_req("de:ad:be:ef:00:01", "HomeNet"))
    mon.observe(_probe_req("de:ad:be:ef:00:01", ""))       # broadcast probe
    for _ in range(9):
        mon.observe(_deauth("aa:bb:cc:00:00:01", "de:ad:be:ef:00:01"))
    rep = mon.report()
    assert rep["aps"]["aa:bb:cc:00:00:01"]["ssid"] == "CorpWiFi"
    assert rep["aps"]["aa:bb:cc:00:00:01"]["beacons"] == 5
    assert rep["aps"]["aa:bb:cc:00:00:02"]["ssid"] == "<hidden>"
    probes = rep["probes"]["de:ad:be:ef:00:01"]
    assert probes["HomeNet"] == 1 and probes["<broadcast>"] == 1
    assert rep["deauths"]["total"] == 9


def test_data_and_control_frames_are_ignored_by_the_monitor():
    from capture.wifi import WifiMonitor
    mon = WifiMonitor()
    mon.observe(_dot11_data(_ipv4_udp()))      # a data frame
    mon.observe(bytes([0xD4, 0x00]) + b"\x00" * 10)   # an ACK (control)
    assert mon.report() == {}


def test_wireless_section_reaches_the_report():
    import tempfile
    from capture.base import group_into_series
    from capture.pcap import PcapSource
    from out.narrate import narrate

    frames = [
        _radiotap(_beacon("aa:bb:cc:00:00:01", "CorpWiFi")),
        _radiotap(_beacon("aa:bb:cc:00:00:01", "CorpWiFi")),
        _radiotap(_probe_req("de:ad:be:ef:00:01", "HomeNet")),
    ] + [_radiotap(_deauth("aa:bb:cc:00:00:01", "de:ad:be:ef:00:01"))
         for _ in range(20)]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "wifi.pcap"
        with open(path, "wb") as h:
            h.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                LINKTYPE_IEEE802_11_RADIOTAP))
            for i, fr in enumerate(frames):
                h.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                    len(fr), len(fr)))
                h.write(fr)
        src = PcapSource(path)
        series = list(src.observations())   # no IP series; that's fine
        text = narrate(series, [], stats=src.stats, source_name="wifi.pcap")
    flat = " ".join(text.split())
    assert "WIRELESS (802.11 management)" in flat
    assert "CorpWiFi" in flat
    assert "HomeNet" in flat
    assert "deauth / disassoc 20 frame(s)" in flat   # flattened single space
    assert "denial-of-service" in flat          # the honest caveat


def test_glossary_covers_wifi_management_vocab():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "beacons name access points; a deauth flood; probe request SSIDs")}
    assert "802.11 / monitor mode / radiotap" in found


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
