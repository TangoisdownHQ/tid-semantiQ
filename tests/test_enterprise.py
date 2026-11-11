"""Cleartext AD-protocol metadata — SMB, Kerberos, LDAP, RDP.

Each parser pulls one high-value thing an internal capture leaks in the
clear: the RDP mstshash username, the SMB dialect and the NTLMSSP target
domain/computer, the Kerberos message type, the LDAP bind DN. All are
bounds-checked (they see hostile, truncated, mid-stream bytes), and the
end-to-end test proves they reach the ENTERPRISE / AD report section.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.enterprise import (
    kerberos_message, ldap_bind_dn, rdp_cookie, smb_info,
)
from capture.pcapfile import LINKTYPE_ETHERNET


# --------------------------------------------------------------------------
# the parsers
# --------------------------------------------------------------------------


def test_rdp_cookie_username():
    pdu = (b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00"
           b"Cookie: mstshash=jdoe\r\n" + b"\x01\x00\x08\x00")
    assert rdp_cookie(pdu) == "jdoe"
    assert rdp_cookie(b"no cookie here") is None


def _ntlmssp_challenge(nb_domain="CORP", nb_computer="DC01"):
    def av(av_id, text):
        raw = text.encode("utf-16-le")
        return struct.pack("<HH", av_id, len(raw)) + raw
    info = av(2, nb_domain) + av(1, nb_computer) + av(4, "corp.example") \
        + struct.pack("<HH", 0, 0)   # MsvAvEOL
    sig = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 2)
    target_name = struct.pack("<HHI", 0, 0, 0)
    flags = b"\x00\x00\x00\x00"
    challenge = b"\x11" * 8
    reserved = b"\x00" * 8
    # TargetInfo fields point past the fixed 48-byte header.
    info_fields = struct.pack("<HHI", len(info), len(info), 48)
    head = sig + msg_type + target_name + flags + challenge + reserved \
        + info_fields
    assert len(head) == 48
    return head + info


def test_smb2_dialect_and_ntlmssp_target():
    # minimal SMB2 negotiate response with dialect 3.1.1 at offset 68
    body = b"\xfeSMB" + b"\x00" * 64
    body += struct.pack("<H", 0x0311)       # dialect field at offset 68
    info = smb_info(body)
    assert info["smb"] == "SMB2/3" and info["smb_dialect"] == "3.1.1"

    # NTLMSSP challenge anywhere in a later SMB message
    payload = b"\xfeSMB" + b"\x00" * 60 + _ntlmssp_challenge("CORP", "DC01")
    info = smb_info(payload)
    assert info["nb_domain"] == "CORP"
    assert info["nb_computer"] == "DC01"
    assert info["dns_domain"] == "corp.example"


def test_smb1_is_recognised():
    assert smb_info(b"\xffSMB" + b"\x00" * 30)["smb"] == "SMB1"


def test_kerberos_message_types():
    assert kerberos_message(b"\x00\x00\x00\x50\x6a\x82") == "AS-REQ"   # TCP
    assert kerberos_message(b"\x6c\x82\x01\x00") == "TGS-REQ"          # UDP
    assert kerberos_message(b"\x7e\x30") == "KRB-ERROR"
    assert kerberos_message(b"\x30\x82\x01\x00") is None              # not krb


def test_ldap_bind_dn():
    dn = b"cn=admin,dc=corp,dc=example"
    name = b"\x04" + bytes([len(dn)]) + dn
    version = b"\x02\x01\x03"
    bind = b"\x60" + bytes([len(version) + len(name)]) + version + name
    mid = b"\x02\x01\x01"
    msg = b"\x30" + bytes([len(mid) + len(bind)]) + mid + bind
    assert ldap_bind_dn(msg) == "cn=admin,dc=corp,dc=example"
    assert ldap_bind_dn(b"\x30\x05notldap") is None


def test_parsers_reject_junk_without_raising():
    for fn in (rdp_cookie, smb_info, kerberos_message, ldap_bind_dn):
        for junk in (b"", b"\x00", b"\xff" * 3, b"NTLMSSP\x00short",
                     b"\x30\x80", b"\x60\x84\xff\xff\xff\xff"):
            fn(junk)   # must not raise


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------


def test_enterprise_metadata_reaches_the_report():
    from capture.base import group_into_series
    from capture.pcap import PcapSource
    from out.narrate import narrate

    def _tcp(src, dst, sport, dport, flags, payload=b""):
        tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                          1024, 0, 0) + payload
        total = 20 + len(tcp)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                         bytes(int(o) for o in src.split(".")),
                         bytes(int(o) for o in dst.split(".")))
        return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + tcp

    rdp = b"\x03\x00\x00\x2cCookie: mstshash=administrator\r\n\x01\x00"
    smb = b"\xfeSMB" + b"\x00" * 60 + _ntlmssp_challenge("CONTOSO", "FS1")
    c, s = "10.0.0.5", "10.0.0.20"
    frames = [
        _tcp(c, s, 50001, 3389, 0x02),
        _tcp(c, s, 50001, 3389, 0x18, rdp),
        _tcp(c, s, 50001, 3389, 0x18, b"more"),
        _tcp(c, s, 50002, 445, 0x02),
        _tcp(s, c, 445, 50002, 0x18, smb),
        _tcp(s, c, 445, 50002, 0x18, b"more"),
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "ad.pcap"
        with open(path, "wb") as h:
            h.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                LINKTYPE_ETHERNET))
            for i, fr in enumerate(frames):
                h.write(struct.pack("<IIII", 1_700_000_000 + i, 0,
                                    len(fr), len(fr)))
                h.write(fr)
        src = PcapSource(path)
        series = list(group_into_series(src.observations(), min_observations=2))
        text = " ".join(narrate(series, [], source_name="ad.pcap").split())
    assert "ENTERPRISE / AD" in text
    assert "administrator" in text      # RDP user
    assert "CONTOSO" in text            # NTLMSSP domain
    assert "FS1" in text                # NTLMSSP computer


def test_glossary_covers_enterprise():
    from out.glossary import terms_in
    found = {t.term for _, t in terms_in(
        "SMB NTLM domain, Kerberos AS-REQ, LDAP bind DN, RDP mstshash")}
    assert "enterprise/AD metadata (SMB, Kerberos, LDAP, RDP)" in found


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
