"""Cleartext service metadata — SSH, NTP, DHCP, mDNS/LLMNR.

Four protocols that state real facts without a key: SSH names its software
in a cleartext banner before encrypting; NTP's first byte says who is asking
whom for time; DHCP carries the name a device calls itself; mDNS and LLMNR
are the LAN's DNS-format name gossip. The tests pin the parsers against
hand-built packets, the plausibility gates (a port number alone must not
make a datagram NTP or DHCP), and the two narrator integrations that turn
the facts into meaning: the SERVICES section, and DHCP hostnames labelling
LAN addresses that nothing ever resolves — at lower priority than any name
the network actually asserted.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.base import group_into_series
from capture.decode import dhcp_info, ntp_info, ssh_banner
from capture.pcap import PcapSource
from capture.pcapfile import LINKTYPE_ETHERNET
from out.narrate import narrate


# --------------------------------------------------------------------------
# packet builders
# --------------------------------------------------------------------------


def _write_pcap(path: Path, frames) -> None:
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, LINKTYPE_ETHERNET))
        for index, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", 1_700_000_000 + index,
                                     index * 1000, len(frame), len(frame)))
            handle.write(frame)


def _ip_udp(src, dst, sport, dport, payload) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
                     bytes(int(o) for o in src.split(".")),
                     bytes(int(o) for o in dst.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + udp


def _ip_tcp(src, dst, sport, dport, flags, payload=b"") -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                      1024, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     bytes(int(o) for o in src.split(".")),
                     bytes(int(o) for o in dst.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + tcp


def _ntp_packet(mode: int, version: int = 4, stratum: int = 2) -> bytes:
    first = (0 << 6) | (version << 3) | mode
    return bytes([first, stratum]) + b"\x00" * 46


def _dhcp_packet(msg_type: int, hostname: str = "", yiaddr: str = "0.0.0.0",
                 requested: str = "") -> bytes:
    head = bytearray(236)
    head[0] = 1 if msg_type in (1, 3, 4, 7, 8) else 2   # op by message kind
    head[16:20] = bytes(int(o) for o in yiaddr.split("."))
    options = bytearray(b"\x63\x82\x53\x63")
    options += bytes([53, 1, msg_type])
    if hostname:
        encoded = hostname.encode()
        options += bytes([12, len(encoded)]) + encoded
    if requested:
        options += bytes([50, 4]) + bytes(int(o) for o in requested.split("."))
    options += b"\xff"
    return bytes(head) + bytes(options)


def _dns_query(qname: str, dport: int, src: str, dst: str,
               sport: int = 5353) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    body = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    body += labels + b"\x00" + struct.pack(">HH", 1, 1)
    return _ip_udp(src, dst, sport, dport, body)


# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------


def test_ssh_banner_is_read_and_bounded():
    assert ssh_banner(b"SSH-2.0-OpenSSH_9.6\r\n...key exchange...") == \
        "SSH-2.0-OpenSSH_9.6"
    assert ssh_banner(b"SSH-2.0-paramiko_3.4.0\n") == "SSH-2.0-paramiko_3.4.0"
    assert ssh_banner(b"GET / HTTP/1.1\r\n") is None
    assert ssh_banner(b"SSH-2.0-") is None            # a prefix is not a banner
    assert ssh_banner(b"SSH-" + b"x" * 300) is None   # over the RFC's 255 cap


def test_ntp_header_is_interpreted():
    client = ntp_info(_ntp_packet(mode=3))
    assert client == (4, "client", None)              # a query has no stratum
    server = ntp_info(_ntp_packet(mode=4, stratum=2))
    assert server.mode == "server" and server.stratum == 2
    assert ntp_info(b"\x00" * 48) is None             # version 0, mode 0
    assert ntp_info(_ntp_packet(mode=3)[:40]) is None  # truncated


def test_dhcp_message_hostname_and_subject_address():
    request = dhcp_info(_dhcp_packet(3, hostname="laptop-jane",
                                     requested="10.0.0.42"))
    assert request.kind == "REQUEST"
    assert request.hostname == "laptop-jane"
    assert request.address == "10.0.0.42"
    ack = dhcp_info(_dhcp_packet(5, yiaddr="10.0.0.42"))
    assert ack.kind == "ACK" and ack.address == "10.0.0.42"
    # No magic cookie -> not DHCP, whatever port it rode on.
    assert dhcp_info(b"\x01" + b"\x00" * 300) is None


def test_port_alone_does_not_make_a_protocol():
    """The plausibility gates: random bytes on 123/67 stay generic UDP."""
    assert ntp_info(b"\xff" * 48) is None              # version 7 is not NTP
    assert dhcp_info(b"\x07" + b"\x00" * 260) is None  # op 7 is not BOOTP


# --------------------------------------------------------------------------
# end to end through the pcap reader
# --------------------------------------------------------------------------


def _narrate_frames(frames) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "t.pcap"
        _write_pcap(path, frames)
        source = PcapSource(path)
        series = list(group_into_series(source.observations()))
    return narrate(series, [], source_name="t.pcap")


def test_ssh_session_names_both_sides_in_services():
    client, server = "10.0.0.5", "10.0.0.9"
    frames = [
        _ip_tcp(client, server, 5555, 22, 0x02),
        _ip_tcp(server, client, 22, 5555, 0x12),
        _ip_tcp(client, server, 5555, 22, 0x18,
                b"SSH-2.0-OpenSSH_9.6\r\n"),
        _ip_tcp(server, client, 22, 5555, 0x18,
                b"SSH-2.0-dropbear_2022.83\r\n"),
        # post-banner traffic: encrypted, shape only
        _ip_tcp(client, server, 5555, 22, 0x18, b"\x00" * 64),
    ]
    text = _narrate_frames(frames)
    assert "SERVICES" in text
    assert "SSH-2.0-OpenSSH_9.6" in text
    assert "SSH-2.0-dropbear_2022.83" in text


def test_ntp_and_dhcp_facts_reach_the_services_section():
    # Two observations per channel: group_into_series prunes one-shot
    # channels by design (a lone observation supports no behaviour).
    host, gw = "10.0.0.5", "10.0.0.1"
    dhcp = _ip_udp("0.0.0.0", "255.255.255.255", 68, 67,
                   _dhcp_packet(3, hostname="laptop-jane",
                                requested="10.0.0.42"))
    frames = [
        _ip_udp(host, gw, 50000, 123, _ntp_packet(mode=3)),
        _ip_udp(gw, host, 123, 50000, _ntp_packet(mode=4, stratum=3)),
        dhcp, dhcp,
    ]
    text = " ".join(_narrate_frames(frames).split())
    assert "client" in text and "server" in text      # ntp modes
    assert "REQUEST" in text
    assert "laptop-jane" in text


def test_dhcp_hostname_labels_the_subject_address_not_zero():
    """The name must attach to the address the exchange was about, and the
    0.0.0.0 an unconfigured client sends from must never be named."""
    dhcp = _ip_udp("0.0.0.0", "255.255.255.255", 68, 67,
                   _dhcp_packet(3, hostname="laptop-jane",
                                requested="10.0.0.42"))
    frames = [
        dhcp, dhcp,   # two: one-shot channels are pruned by design
        # give 10.0.0.42 some traffic so it appears in host detail
        _ip_udp("10.0.0.42", "10.0.0.1", 40000, 9999, b"ping"),
        _ip_udp("10.0.0.42", "10.0.0.1", 40000, 9999, b"ping"),
    ]
    text = _narrate_frames(frames)
    assert "laptop-jane" in text
    assert "0.0.0.0  laptop-jane" not in text


def test_mdns_is_tagged_and_kept_apart_from_resolver_dns():
    frames = [
        _dns_query("printer.local", 5353, "10.0.0.5", "224.0.0.251"),
        _dns_query("printer.local", 5353, "10.0.0.5", "224.0.0.251"),
        _dns_query("shop.test", 53, "10.0.0.5", "10.0.0.1", sport=40000),
        _dns_query("shop.test", 53, "10.0.0.5", "10.0.0.1", sport=40000),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "t.pcap"
        _write_pcap(path, frames)
        source = PcapSource(path)
        series = list(group_into_series(source.observations()))
    mdns = [s for s in series if s.channel.dims.get("service") == "mdns"]
    plain = [s for s in series if s.channel.domain == "dns"
             and not s.channel.dims.get("service")]
    assert len(mdns) == 1, [s.channel.dims for s in series]
    assert plain, "resolver DNS must still parse untagged"
    # separate channels: the mdns query must not share a key with plain DNS
    assert mdns[0].channel.key != plain[0].channel.key


def test_glossary_covers_the_new_vocabulary():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "SSH banner seen; NTP stratum 2; DHCP REQUEST; mDNS gossip")}
    assert "SSH banner" in found
    assert "NTP / stratum" in found
    assert "DHCP" in found
    assert "mDNS / LLMNR" in found


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
