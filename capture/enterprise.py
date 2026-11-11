"""Cleartext metadata from the enterprise/AD protocols — SMB, Kerberos, LDAP, RDP.

An internal capture is full of Active-Directory traffic, and these four leak
real reconnaissance before (or without) any encryption — the same "meaning
without a key" the SSH/NTP/DHCP parsers already pull from their protocols:

  RDP  — the X.224 connection request carries a routing cookie,
         `Cookie: mstshash=<username>`, so the account someone is logging in
         as is in the first client packet, in the clear.
  SMB  — the dialect negotiated, and the NTLMSSP challenge the server sends
         back, which names the DOMAIN, the computer, and their DNS forms —
         an AD map handed over for free.
  KRB  — Kerberos message type (AS-REQ/TGS-REQ/…). An AS-REQ is where a
         client states the username it is authenticating as; recognising it
         marks where that identity sits even when a deeper parse is declined.
  LDAP — a BindRequest carries the bind DN (the account) in the clear unless
         LDAPS/StartTLS is used.

Every parser is bounds-checked to the hilt and returns None on anything that
does not fit exactly: these see hostile, truncated, mid-stream bytes, and the
fuzz suite feeds them random input. None of them decrypts anything.
"""

from __future__ import annotations

import struct
from typing import Dict, Optional

__all__ = ["rdp_cookie", "smb_info", "kerberos_message", "ldap_bind_dn"]


def rdp_cookie(payload: bytes) -> Optional[str]:
    """The `mstshash` username from an RDP X.224 connection request."""
    marker = b"Cookie: mstshash="
    i = payload.find(marker)
    if i < 0:
        return None
    rest = payload[i + len(marker):]
    end = rest.find(b"\r\n")
    user = rest[:end if end >= 0 else 40]
    try:
        text = user.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text or None


# --------------------------------------------------------------------------
# SMB + NTLMSSP
# --------------------------------------------------------------------------

_SMB2_DIALECTS = {
    0x0202: "2.0.2", 0x0210: "2.1", 0x0222: "2.2.2", 0x0224: "2.2.4",
    0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02FF: "2.x (wildcard)",
}
# NTLMSSP AV_PAIR ids that name the target.
_AV = {1: "nb_computer", 2: "nb_domain", 3: "dns_computer", 4: "dns_domain"}


def _utf16(raw: bytes) -> str:
    return raw.decode("utf-16-le", "replace").rstrip("\x00")


def smb_info(payload: bytes) -> Optional[Dict[str, str]]:
    """SMB dialect and, where present, the NTLMSSP target domain/computer.

    Handles the NetBIOS session wrapper (4-byte length) that precedes SMB on
    445/139, then the SMB2 header. The NTLMSSP Type-2 challenge is found by
    its signature anywhere in the payload, since it arrives a few messages
    into the session rather than first.
    """
    out: Dict[str, str] = {}
    body = payload
    # Strip the 4-byte NetBIOS session header if it is there.
    if len(body) >= 4 and body[0] == 0x00:
        length = (body[1] << 16) | (body[2] << 8) | body[3]
        if 0 < length <= len(body) - 4:
            body = body[4:4 + length]

    if body[:4] == b"\xfeSMB":
        out["smb"] = "SMB2/3"
        # Negotiate response: DialectRevision sits at offset 68 — the 64-byte
        # SMB2 header plus StructureSize(2) + SecurityMode(2).
        if len(body) >= 70:
            dialect = struct.unpack("<H", body[68:70])[0]
            name = _SMB2_DIALECTS.get(dialect)
            if name:
                out["smb_dialect"] = name
    elif body[:4] == b"\xffSMB":
        out["smb"] = "SMB1"

    ntlm = _ntlmssp_target(payload)
    if ntlm:
        out.update(ntlm)
    return out or None


def _ntlmssp_target(payload: bytes) -> Dict[str, str]:
    """Target domain/computer (and DNS forms) from an NTLMSSP CHALLENGE."""
    start = payload.find(b"NTLMSSP\x00")
    if start < 0 or start + 48 > len(payload):
        return {}
    if struct.unpack("<I", payload[start + 8:start + 12])[0] != 2:
        return {}   # message type 2 = CHALLENGE (the one that names targets)
    info_len = struct.unpack("<H", payload[start + 40:start + 42])[0]
    info_off = struct.unpack("<I", payload[start + 44:start + 48])[0]
    base = start + info_off
    if info_len <= 0 or base + info_len > len(payload):
        return {}
    out: Dict[str, str] = {}
    pos = base
    end = base + info_len
    while pos + 4 <= end:
        av_id = struct.unpack("<H", payload[pos:pos + 2])[0]
        av_len = struct.unpack("<H", payload[pos + 2:pos + 4])[0]
        value = payload[pos + 4:pos + 4 + av_len]
        if av_id == 0:            # MsvAvEOL
            break
        key = _AV.get(av_id)
        if key and len(value) == av_len:
            out[key] = _utf16(value)
        pos += 4 + av_len
    return out


# --------------------------------------------------------------------------
# Kerberos
# --------------------------------------------------------------------------

#: ASN.1 [APPLICATION n] tags for the Kerberos messages worth naming.
_KRB_APP = {
    10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
    14: "AP-REQ", 15: "AP-REP", 30: "KRB-ERROR",
}


def kerberos_message(payload: bytes) -> Optional[str]:
    """The Kerberos message type from its leading ASN.1 APPLICATION tag.

    Over TCP a 4-byte length prefixes the message; over UDP it does not, so
    both framings are tried. The application number (AS-REQ is where a client
    states its username) is the honest, robust signal; a full principal-name
    parse is deliberately not attempted here.
    """
    for candidate in (payload[4:5], payload[:1]):
        if len(candidate) == 1 and (candidate[0] & 0xE0) == 0x60:
            app = candidate[0] & 0x1F
            name = _KRB_APP.get(app)
            if name:
                return name
    return None


# --------------------------------------------------------------------------
# LDAP
# --------------------------------------------------------------------------


def ldap_bind_dn(payload: bytes) -> Optional[str]:
    """The bind DN (the account) from an LDAP BindRequest, in the clear.

    LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE }, where
    a BindRequest is [APPLICATION 0] { version INTEGER, name LDAPDN (OCTET
    STRING) ... }. We walk just far enough to read that OCTET STRING.
    """
    if len(payload) < 7 or payload[0] != 0x30:   # LDAPMessage SEQUENCE
        return None
    pos, _ = _asn1_len(payload, 1)
    if pos is None:
        return None
    # messageID INTEGER
    if pos >= len(payload) or payload[pos] != 0x02:
        return None
    pos, mid_len = _asn1_len(payload, pos + 1)
    if pos is None:
        return None
    pos += mid_len
    # protocolOp: BindRequest is [APPLICATION 0] constructed = 0x60
    if pos >= len(payload) or payload[pos] != 0x60:
        return None
    pos, _ = _asn1_len(payload, pos + 1)
    if pos is None:
        return None
    # version INTEGER
    if pos >= len(payload) or payload[pos] != 0x02:
        return None
    pos, ver_len = _asn1_len(payload, pos + 1)
    if pos is None:
        return None
    pos += ver_len
    # name: OCTET STRING = the bind DN
    if pos >= len(payload) or payload[pos] != 0x04:
        return None
    pos, dn_len = _asn1_len(payload, pos + 1)
    if pos is None or pos + dn_len > len(payload):
        return None
    dn = payload[pos:pos + dn_len]
    try:
        return dn.decode("utf-8") or "<anonymous>"
    except UnicodeDecodeError:
        return None


def _asn1_len(buf: bytes, pos: int):
    """(position after the length octets, length value), or (None, None)."""
    if pos >= len(buf):
        return None, None
    first = buf[pos]
    if first < 0x80:
        return pos + 1, first
    n = first & 0x7F
    if n == 0 or n > 4 or pos + 1 + n > len(buf):
        return None, None
    value = 0
    for b in buf[pos + 1:pos + 1 + n]:
        value = (value << 8) | b
    return pos + 1 + n, value
