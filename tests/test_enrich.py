"""Offline endpoint enrichment — who announces it, whose cloud it sits in.

The engine consumes datasets the operator supplies and changes nothing when
none are given. The honesty properties under test: private space is never
attributed (a dataset row squatting 10/8 must not label a LAN printer), a
cloud hit names the landlord with the tenant caveat in the narration, three
different providers' file shapes auto-detect, and an unrecognised file is a
loud error rather than a silently unattributed report.
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.enrich import Enricher
from core.model import Channel, Direction, Entity, Locus, Observation, Series
from out.narrate import narrate


# --------------------------------------------------------------------------
# dataset builders
# --------------------------------------------------------------------------

_ASN_TSV = (
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
    "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n"
    "10.0.0.0\t10.255.255.255\t64512\tZZ\tSQUATTER-ON-PRIVATE\n"
    "203.0.113.0\t203.0.113.255\t0\tNone\tNot routed\n"
    "2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET\n"
)

_AWS_JSON = {"syncToken": "1", "prefixes": [
    {"ip_prefix": "52.95.0.0/16", "region": "us-east-1", "service": "EC2"},
]}
_GCP_JSON = {"prefixes": [
    {"ipv4Prefix": "34.0.0.0/16", "scope": "us-central1",
     "service": "Google Cloud"},
]}
_AZURE_JSON = {"values": [
    {"name": "Storage.EastUS", "properties": {
        "region": "eastus", "systemService": "AzureStorage",
        "addressPrefixes": ["20.60.0.0/16"]}},
]}


def _enricher(tmp: Path, asn: bool = True, clouds=("aws",)) -> Enricher:
    enricher = Enricher()
    if asn:
        path = tmp / "ip2asn.tsv"
        path.write_text(_ASN_TSV)
        enricher.load_asn_tsv(path)
    documents = {"aws": _AWS_JSON, "gcp": _GCP_JSON, "azure": _AZURE_JSON}
    for name in clouds:
        path = tmp / f"{name}.json"
        path.write_text(json.dumps(documents[name]))
        enricher.load_cloud_json(path)
    return enricher


# --------------------------------------------------------------------------
# lookup
# --------------------------------------------------------------------------


def test_asn_lookup_v4_and_v6():
    with tempfile.TemporaryDirectory() as d:
        enricher = _enricher(Path(d), clouds=())
    hit = enricher.lookup("1.0.0.99")
    assert hit.asn == 13335 and hit.as_name == "CLOUDFLARENET"
    assert hit.country == "US"
    v6 = enricher.lookup("2606:4700::1111")
    assert v6.asn == 13335
    assert enricher.lookup("9.9.9.9") is None        # outside every range


def test_not_routed_rows_are_dropped():
    """AS0 is the dataset's 'not announced' marker, not an attribution."""
    with tempfile.TemporaryDirectory() as d:
        enricher = _enricher(Path(d), clouds=())
    assert enricher.lookup("203.0.113.9") is None


def test_private_space_is_never_attributed():
    """The TSV above deliberately covers 10/8 — the lookup must refuse to
    attribute private space regardless of what a dataset claims."""
    with tempfile.TemporaryDirectory() as d:
        enricher = _enricher(Path(d), clouds=())
    assert enricher.lookup("10.1.2.3") is None
    assert enricher.lookup("127.0.0.1") is None
    assert enricher.lookup("not-an-ip") is None


def test_all_three_cloud_shapes_auto_detect():
    with tempfile.TemporaryDirectory() as d:
        enricher = _enricher(Path(d), asn=False,
                             clouds=("aws", "gcp", "azure"))
    aws = enricher.lookup("52.95.1.2")
    assert (aws.provider, aws.region, aws.service) == \
        ("AWS", "us-east-1", "EC2")
    gcp = enricher.lookup("34.0.5.6")
    assert gcp.provider == "GCP" and gcp.region == "us-central1"
    azure = enricher.lookup("20.60.9.9")
    assert azure.provider == "Azure" and azure.service == "AzureStorage"
    assert "AWS" in enricher.describe() and "Azure" in enricher.describe()


def test_asn_and_cloud_combine_in_one_answer():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        enricher = Enricher()
        (tmp / "asn.tsv").write_text(
            "52.95.0.0\t52.95.255.255\t16509\tUS\tAMAZON-02\n")
        enricher.load_asn_tsv(tmp / "asn.tsv")
        (tmp / "aws.json").write_text(json.dumps(_AWS_JSON))
        enricher.load_cloud_json(tmp / "aws.json")
    hit = enricher.lookup("52.95.1.2")
    assert hit.asn == 16509 and hit.provider == "AWS"


def test_gzipped_tsv_loads():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "ip2asn.tsv.gz"
        with gzip.open(path, "wt") as handle:
            handle.write(_ASN_TSV)
        enricher = Enricher()
        assert enricher.load_asn_tsv(path) > 0
    assert enricher.lookup("8.8.8.8").asn == 15169


def test_unrecognised_cloud_file_is_a_loud_error():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "weird.json"
        path.write_text(json.dumps({"something": "else"}))
        enricher = Enricher()
        try:
            enricher.load_cloud_json(path)
        except ValueError as error:
            assert "not a recognised" in str(error)
        else:
            raise AssertionError("expected ValueError")


def test_unloaded_enricher_changes_nothing():
    enricher = Enricher()
    assert not enricher.loaded
    assert enricher.lookup("8.8.8.8") is None


# --------------------------------------------------------------------------
# narration
# --------------------------------------------------------------------------


def _series(responder: str) -> Series:
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443"},
        initiator=Entity("ip", "192.168.1.5", labels={"private": True}),
        responder=Entity("ip", responder, labels={"private": False}),
    )
    observations = [
        Observation(ts=1_700_000_000.0 + i, channel=channel,
                    direction=Direction.EGRESS, size=400, kind="tcp_burst",
                    attrs={"encrypted": True},
                    locus=Locus(source="t.pcap", frames=(i + 1,)))
        for i in range(4)
    ]
    return Series(channel, observations)


def test_endpoint_dossier_carries_attribution_with_the_tenant_caveat():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        enricher = Enricher()
        (tmp / "asn.tsv").write_text(
            "52.95.0.0\t52.95.255.255\t16509\tUS\tAMAZON-02\n")
        enricher.load_asn_tsv(tmp / "asn.tsv")
        (tmp / "aws.json").write_text(json.dumps(_AWS_JSON))
        enricher.load_cloud_json(tmp / "aws.json")
    text = " ".join(narrate([_series("52.95.1.2")], [],
                            source_name="t.pcap",
                            enricher=enricher).split())
    assert "AS16509 AMAZON-02 (US)" in text
    assert "in AWS us-east-1, EC2" in text
    assert "landlord" in text                       # the tenant caveat
    assert "no lookup leaves this machine" in text  # the sources line


def test_without_enricher_the_report_is_unchanged():
    base = narrate([_series("52.95.1.2")], [], source_name="t.pcap")
    explicit = narrate([_series("52.95.1.2")], [], source_name="t.pcap",
                       enricher=None)
    assert base == explicit
    assert "announced by" not in base


def test_glossary_covers_attribution():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in("announced by AS13335")}
    assert "ASN / cloud attribution" in found


# --------------------------------------------------------------------------
# MAC / OUI vendor naming
# --------------------------------------------------------------------------

_MANUF = (
    "# a manuf-format OUI table\n"
    "00:00:0C\tCisco\tCisco Systems, Inc\n"
    "B8:27:EB\tRaspberryPi\tRaspberry Pi Foundation\n"
    "28:6F:B9\tNokia\tNokia Shanghai Bell Co., Ltd.\n"
    "70:B3:D5:3A:B0:00/36\tTinyVendor\tA Small MA-S Assignee\n"
)


def _oui_enricher(tmp: Path):
    from core.enrich import Enricher
    path = tmp / "manuf"
    path.write_text(_MANUF)
    enricher = Enricher()
    enricher.load_oui_manuf(path)
    return enricher


def test_oui_lookup_24_bit_vendor():
    with tempfile.TemporaryDirectory() as d:
        enricher = _oui_enricher(Path(d))
    assert enricher.lookup_mac("b8:27:eb:1a:2b:3c") == "Raspberry Pi Foundation"
    assert enricher.lookup_mac("00:00:0c:ff:ee:dd") == "Cisco Systems, Inc"
    assert enricher.lookup_mac("ac:de:48:00:11:22") is None   # not in table


def test_longer_ma_s_prefix_wins_over_its_24_bit_block():
    with tempfile.TemporaryDirectory() as d:
        enricher = _oui_enricher(Path(d))
    # 70:b3:d5 is the IEEE-registered block shared by many MA-S assignees;
    # the 36-bit entry is more specific and must win for its sub-range.
    assert enricher.lookup_mac("70:b3:d5:3a:b0:99") == "A Small MA-S Assignee"


def test_randomised_and_multicast_macs_name_no_vendor():
    with tempfile.TemporaryDirectory() as d:
        enricher = _oui_enricher(Path(d))
    # locally-administered bit (0x02) set in the first octet -> randomised
    assert enricher.lookup_mac("b8:27:eb:1a:2b:3c") is not None
    assert enricher.lookup_mac("ba:27:eb:1a:2b:3c") is None   # 0xba = ...10
    assert enricher.lookup_mac("01:00:5e:00:00:fb") is None   # multicast


def test_mac_extraction_only_from_ethernet():
    from capture.decode import ethernet_src_mac
    from capture.pcapfile import LINKTYPE_ETHERNET, LINKTYPE_RAW
    frame = bytes.fromhex("ffffffffffff" "b827eb1a2b3c" "0800") + b"\x00" * 20
    assert ethernet_src_mac(LINKTYPE_ETHERNET, frame) == "b8:27:eb:1a:2b:3c"
    assert ethernet_src_mac(LINKTYPE_RAW, frame) is None
    assert ethernet_src_mac(LINKTYPE_ETHERNET, b"\x00" * 4) is None


def test_host_detail_names_a_lan_device_by_vendor():
    import struct
    from capture.base import group_into_series
    from capture.pcap import PcapSource
    from capture.pcapfile import LINKTYPE_ETHERNET

    def _eth_udp(src_mac, src_ip, dst_ip):
        udp = struct.pack(">HHHH", 40000, 9999, 12, 0) + b"ping"
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64,
                         17, 0,
                         bytes(int(o) for o in src_ip.split(".")),
                         bytes(int(o) for o in dst_ip.split(".")))
        return (bytes.fromhex("ffffffffffff") + bytes.fromhex(src_mac)
                + b"\x08\x00" + ip + udp)

    frames = [
        _eth_udp("b827eb1a2b3c", "10.0.0.50", "10.0.0.1"),
        _eth_udp("b827eb1a2b3c", "10.0.0.50", "10.0.0.1"),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.pcap"
        with open(path, "wb") as handle:
            handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                     65535, LINKTYPE_ETHERNET))
            for i, frame in enumerate(frames):
                handle.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                         len(frame), len(frame)))
                handle.write(frame)
        source = PcapSource(path)
        series = list(group_into_series(source.observations()))
        enricher = _oui_enricher(Path(d))
        text = narrate(series, [], source_name="t.pcap",
                       enricher=enricher, stats=source.stats)
    assert "10.0.0.50" in source.stats["host_macs"]
    assert "Raspberry Pi Foundation" in text
    assert "b8:27:eb:1a:2b:3c" in text


def test_glossary_covers_mac_vendor():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "the device's MAC OUI names the hardware vendor")}
    assert "MAC / OUI vendor" in found


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
