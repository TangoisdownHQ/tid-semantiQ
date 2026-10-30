"""TsharkSource — capture via Wireshark's dissectors.

WHY THIS EXISTS AND WHY IT IS THE CRITICAL PATH.

Assisted mode needs decrypted TLS, and pure-stdlib TLS 1.3 decryption is not
feasible: it requires the HKDF-Expand-Label key schedule plus AES-GCM or
ChaCha20-Poly1305 AEAD, and `hashlib`/`hmac` provide no AEAD. The options were
to depend on `cryptography` and hand-write a security-critical key schedule,
or to delegate. Delegating wins outright:

    tshark -r cap.pcap -o tls.keylog_file:keys.log -T ek

tshark does the decryption and the dissection, and hands back JSON. Zero
crypto written here, and every Wireshark dissector arrives with it —
HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC and protobuf now, Modbus, DNP3 and
MAVLink later, none of which need a parser written.

`capture/pcap.py` remains the native path: it is faster, dependency-free, and
sufficient for behavioural analysis of TCP/TLS/DNS metadata, which needs no
decryption. Use the native reader for cadence and volume; use this one when
the finding is in the content.

PROFILES. A profile declares the display filter, the field list, and how to
turn one dissected frame into an `Observation`. Adding a protocol is a
profile — no change to this file, and no change to anything above it.
"""

from __future__ import annotations

import binascii
import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

from capture.base import CaptureSource
from core.model import Channel, Direction, Entity, Locus, Observation

__all__ = [
    "TsharkSource", "TsharkProfile", "HttpProfile", "ModbusProfile",
    "Dnp3Profile", "TsharkUnavailable",
    "MODBUS_WRITE_CODES", "MODBUS_READ_CODES", "DNP3_CONTROL_CODES",
]


class TsharkUnavailable(RuntimeError):
    pass


# --------------------------------------------------------------------------
# field validation
# --------------------------------------------------------------------------
#
# Field names are not stable across Wireshark releases — `http.origin` does
# not exist in every build, and tshark exits 1 on an unknown `-e`, killing
# the whole run. Validating once (about 0.2s) makes a profile portable: a
# field that is absent is dropped and reported, rather than taking the
# capture with it.
#
# Dropping is the right failure mode here because fields are additive
# evidence. Losing one costs an inspector some context; aborting costs the
# operator the entire analysis.

_KNOWN_FIELDS: Optional[frozenset] = None


def known_fields(tshark: str = "tshark") -> frozenset:
    global _KNOWN_FIELDS
    if _KNOWN_FIELDS is None:
        try:
            proc = subprocess.run(
                [tshark, "-G", "fields"],
                capture_output=True, text=True, timeout=60, check=False,
            )
            names = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                # Field records are "F<tab>description<tab>abbrev<tab>..."
                if len(parts) >= 3 and parts[0] == "F":
                    names.add(parts[2])
            _KNOWN_FIELDS = frozenset(names)
        except (OSError, subprocess.SubprocessError):
            # Could not ask: assume every field is fine and let tshark
            # complain, rather than silently analysing nothing.
            _KNOWN_FIELDS = frozenset()
    return _KNOWN_FIELDS


# --------------------------------------------------------------------------
# ek field access
# --------------------------------------------------------------------------
#
# `-T ek` returns every field as an ARRAY OF STRINGS, and omits absent fields
# entirely. Both matter: a missing field is None rather than empty, and a
# single-valued field still arrives wrapped. Field names have dots replaced
# by underscores.


def one(layers: Mapping[str, Any], field: str) -> Optional[str]:
    values = layers.get(field)
    if not values:
        return None
    return values[0] if isinstance(values, list) else str(values)


def many(layers: Mapping[str, Any], field: str) -> Tuple[str, ...]:
    values = layers.get(field)
    if not values:
        return ()
    return tuple(values) if isinstance(values, list) else (str(values),)


def as_int(value: Optional[str], default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def unhex(value: Optional[str]) -> Optional[bytes]:
    """`http.file_data` arrives hex-encoded in ek output."""
    if not value:
        return None
    try:
        return binascii.unhexlify(value.replace(":", ""))
    except (binascii.Error, ValueError):
        return None


# --------------------------------------------------------------------------
# profiles
# --------------------------------------------------------------------------


class TsharkProfile(ABC):
    """Declares what to ask tshark for, and how to read the answer.

    Profiles may hold per-capture state — `HttpProfile` carries an SNI map
    keyed by TCP stream, because SNI appears on the ClientHello frame and not
    on the HTTP frames that need it. One profile instance per source.
    """

    domain: str = ""
    display_filter: str = ""
    fields: Tuple[str, ...] = ()

    @abstractmethod
    def build(self, layers: Mapping[str, Any], source: str,
              retain_payloads: bool) -> Optional[Observation]:
        """One dissected frame -> one Observation, or None to skip it."""
        raise NotImplementedError


_COMMON_FIELDS = (
    "frame.number", "frame.time_epoch",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport",
)


class HttpProfile(TsharkProfile):
    """HTTP/1.x and HTTP/2 transactions, decrypted where keys allow.

    CHANNEL GRANULARITY — the consequential choice, per the spec's §3.

    dims are `{scheme, host}`: the channel is a HOST, not an endpoint, and
    method/path/status live in `attrs`. That is what makes the highest-value
    bug-bounty outputs expressible, because they are all cardinality
    questions at host level:

        endpoint inventory    Fanout(attr="path")
        parameter inventory   Fanout(attr="param")
        third-party flow map  one channel per destination host

    The cost is precision in a finding's title: it names the host, and the
    specific path appears in the inspection's facts and its display filter.
    Per-endpoint statistics (response-time differentials by endpoint) would
    want endpoint-level dims and are deferred rather than smuggled in — one
    transaction must not be emitted on two channels, or every count is wrong.
    """

    domain = "http"
    # Also admit ClientHello frames, purely to harvest SNI. They are not
    # HTTP, so `build` records and discards them.
    display_filter = "http || tls.handshake.type == 1"
    fields = _COMMON_FIELDS + (
        "tls.handshake.extensions_server_name",
        "http.request.method", "http.request.full_uri", "http.request.uri",
        "http.host", "http.request.line", "http.response.line",
        "http.authorization", "http.cookie", "http.set_cookie",
        "http.response.code", "http.content_type", "http.file_data",
        "http.referer", "http.user_agent", "http.location",
        "http.request.version", "http.response.version",
        # Wireshark's own request/response pairing and timing. Using these
        # rather than computing them here is not laziness: `http.request_in`
        # is correct across keep-alive and pipelining, where several
        # transactions share one `tcp.stream` and any stream-based pairing
        # would mis-associate them.
        "http.time", "http.request_in",
        "http2.streamid",
    )

    def __init__(self) -> None:
        self._sni: Dict[str, str] = {}
        # Per-stream request context carried forward onto the response.
        # CORS reflection can only be judged by comparing the response's
        # Allow-Origin against the request's Origin, and those arrive as two
        # separate observations — so the request side is remembered here.
        self._origin: Dict[str, str] = {}
        self._request_path: Dict[str, str] = {}
        # Streams that have already produced a response. The FIRST response
        # on a connection carries TCP slow start, pool initialisation and
        # whatever the server does cold — systematically slower for reasons
        # unrelated to the application, and two of them in a sample of ten
        # fabricate a latency cluster.
        self._answered: Set[str] = set()

    def build(self, layers, source, retain_payloads):
        stream = one(layers, "tcp_stream") or "-"

        sni = one(layers, "tls_handshake_extensions_server_name")
        if sni:
            self._sni[stream] = sni
            return None

        method = one(layers, "http_request_method")
        status = one(layers, "http_response_code")
        if not method and not status:
            return None

        is_request = method is not None
        src = one(layers, "ip_src") or one(layers, "ipv6_src") or "?"
        dst = one(layers, "ip_dst") or one(layers, "ipv6_dst") or "?"
        client, server = (src, dst) if is_request else (dst, src)

        full_uri = one(layers, "http_request_full_uri") or ""
        split = urlsplit(full_uri) if full_uri else None
        host = (
            one(layers, "http_host")
            or (split.hostname if split else None)
            or self._sni.get(stream)
            or server
        )
        scheme = (split.scheme if split and split.scheme else None) or (
            "https" if one(layers, "tcp_dstport") == "443" else "http"
        )

        headers = _parse_headers(
            many(layers, "http_request_line" if is_request else "http_response_line")
        )
        body = unhex(one(layers, "http_file_data"))

        path = split.path if split else (one(layers, "http_request_uri") or "")
        params = tuple(k for k, _ in parse_qsl(split.query)) if split and split.query else ()

        frame_number = as_int(one(layers, "frame_number"), 0) or 0

        attrs: Dict[str, Any] = {
            "encrypted": scheme == "https",
            "decrypted": True,
            "host": host,
            "path": path or "/",
            "headers": headers,
            # CONNECTION id, not a transaction id. HTTP keep-alive puts many
            # transactions on one stream, so grouping by `stream` does NOT
            # pair a request with its response — use `txn`.
            "stream": stream,
            "http2_stream": one(layers, "http2_streamid") or "",
        }
        if is_request:
            # A request's own frame number is the transaction id; the matching
            # response carries it back as `http.request_in`.
            attrs["txn"] = f"{stream}:{frame_number}"
            origin = headers.get("origin", "")
            if origin:
                self._origin[stream] = origin
            self._request_path[stream] = path or "/"
            attrs.update({
                "method": method,
                "full_uri": full_uri,
                "query": split.query if split else "",
                "params": params,
                "authorization": one(layers, "http_authorization") or "",
                "cookie": one(layers, "http_cookie") or "",
                "referer": one(layers, "http_referer") or "",
                "user_agent": one(layers, "http_user_agent") or "",
                "body_text": _text(body),
            })
        else:
            request_frame = as_int(one(layers, "http_request_in"))
            if request_frame is not None:
                attrs["txn"] = f"{stream}:{request_frame}"
                attrs["request_frame"] = str(request_frame)
            # `http.time` is seconds since the matching request. Absent when
            # Wireshark could not pair the response — left unset rather than
            # zeroed, so a consumer can tell "fast" from "unknown".
            elapsed = one(layers, "http_time")
            if elapsed is not None:
                try:
                    attrs["elapsed_s"] = float(elapsed)
                except ValueError:
                    pass
            attrs["connection_warm_up"] = stream not in self._answered
            self._answered.add(stream)
            attrs.update({
                "request_origin": self._origin.get(stream, ""),
                "request_path": self._request_path.get(stream, path or "/"),
                "status": status,
                "content_type": one(layers, "http_content_type") or "",
                "set_cookie": many(layers, "http_set_cookie"),
                "location": one(layers, "http_location") or "",
                "body_text": _text(body),
            })

        # Application message size: headers plus body. Using body alone would
        # make a header-heavy request look empty to `Asymmetry`.
        header_bytes = sum(len(k) + len(v) + 4 for k, v in headers.items())
        size = header_bytes + (len(body) if body else 0)

        return Observation(
            ts=float(one(layers, "frame_time_epoch") or 0.0),
            channel=Channel(
                domain="http",
                dims={"scheme": scheme, "host": str(host)},
                initiator=Entity("ip", client),
                responder=Entity("ip", server),
            ),
            direction=Direction.EGRESS if is_request else Direction.INGRESS,
            size=size,
            kind="http_request" if is_request else "http_response",
            wire_size=None,
            attrs=attrs,
            payload=body if retain_payloads else None,
            locus=Locus(
                source=source,
                frames=(as_int(one(layers, "frame_number"), 0) or 0,),
                stream=as_int(stream),
            ),
        )


def _parse_headers(lines: Sequence[str]) -> Dict[str, str]:
    """`http.request.line` gives raw `Name: value\\r\\n` strings.

    Names are lowercased for lookup. Repeated headers are joined with ", "
    rather than overwritten — losing a second `Set-Cookie` would silently
    drop a finding.
    """
    headers: Dict[str, str] = {}
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        key = name.strip().lower()
        val = value.strip()
        headers[key] = f"{headers[key]}, {val}" if key in headers else val
    return headers


def _text(body: Optional[bytes], limit: int = 65536) -> str:
    if not body:
        return ""
    return body[:limit].decode("utf-8", "replace")


# --------------------------------------------------------------------------
# modbus
# --------------------------------------------------------------------------


#: The registered Modbus/TCP server port. Used only as the last resort in
#: deciding request vs response — see `ModbusProfile.build`.
MODBUS_PORT = 502

#: Function codes that CHANGE something. The read/write split is the whole
#: basis of the ICS findings: a host that only ever reads suddenly writing is
#: the event worth alerting on.
MODBUS_WRITE_CODES = {
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
}
MODBUS_READ_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    7: "Read Exception Status",
    20: "Read File Record",
    24: "Read FIFO Queue",
}
#: Diagnostic and management codes. Not writes to a process variable, but not
#: innocent either — 8/subfunction 1 restarts communications.
MODBUS_CONTROL_CODES = {
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    17: "Report Server ID",
    21: "Write File Record",
    43: "Encapsulated Interface Transport",
}


class ModbusProfile(TsharkProfile):
    """Modbus/TCP transactions.

    THE POINT OF THIS CLASS is that it is almost empty. Onboarding Modbus
    took a field list, a `dims` choice and an attribute mapping — no parser,
    no new statistics, and no change to anything above `capture/`. That was
    the architectural claim the project has been making since the spec, and
    this is the test of it.

    Two things arrive free from Wireshark and are worth naming, because
    hand-rolling either would have been the bulk of the work:

        modbus.request_frame   pairs a response to its request, correctly
                               across a long-lived connection carrying
                               hundreds of transactions
        modbus.response_time   seconds from request to response

    Those are the same two facts `HttpProfile` needs, under different names,
    which is why `ResponseTimeDifferential` works here unchanged — it takes
    its attribute names as parameters.

    CHANNEL GRANULARITY. dims are `{"proto": "modbus"}` only, with unit id
    and function code in `attrs`. The spec's original sketch had
    `{"unit": ..., "fn": ...}`, and that would have been the same mistake
    made twice before: putting a value in `dims` makes it uncountable, so
    `Fanout` could not detect unit-id or function-code enumeration — which
    is the scanning signature. Identity is the (master, PLC) pair, so rarity
    answers "a host that has never spoken to this PLC just did".
    """

    domain = "modbus"
    display_filter = "modbus"
    fields = _COMMON_FIELDS + (
        "frame.len",
        "mbtcp.trans_id", "mbtcp.unit_id",
        "modbus.func_code", "modbus.exception_code",
        "modbus.request_frame", "modbus.response_time",
        "modbus.reference_num", "modbus.word_cnt", "modbus.bit_cnt",
    )

    def build(self, layers, source, retain_payloads):
        fc = as_int(one(layers, "modbus_func_code"))
        if fc is None:
            return None

        stream = one(layers, "tcp_stream") or "-"
        frame_number = as_int(one(layers, "frame_number"), 0) or 0
        request_frame = as_int(one(layers, "modbus_request_frame"))

        exception = as_int(one(layers, "modbus_exception_code"))
        srcport = one(layers, "tcp_srcport") or ""
        dstport = one(layers, "tcp_dstport") or ""

        # DIRECTION. The obvious test — "a response is the one carrying
        # `modbus.request_frame`" — is wrong, and wrong in a way that
        # fabricates data: Wireshark does not populate `request_frame` on
        # EXCEPTION responses, so every exception was classified as a
        # request, with master and PLC swapped. On a scanning capture that
        # invented a whole third channel in which the PLC appeared to be
        # issuing commands to the scanner.
        #
        # So the tests run most-reliable first, and the port decides when
        # nothing else does.
        if request_frame is not None or exception is not None:
            is_request = False
        elif srcport == str(MODBUS_PORT):
            is_request = False
        else:
            is_request = True

        src = one(layers, "ip_src") or one(layers, "ipv6_src") or "?"
        dst = one(layers, "ip_dst") or one(layers, "ipv6_dst") or "?"
        master, plc = (src, dst) if is_request else (dst, src)

        unit = one(layers, "mbtcp_unit_id") or "?"

        if fc in MODBUS_WRITE_CODES:
            category, fc_name = "write", MODBUS_WRITE_CODES[fc]
        elif fc in MODBUS_READ_CODES:
            category, fc_name = "read", MODBUS_READ_CODES[fc]
        elif fc in MODBUS_CONTROL_CODES:
            category, fc_name = "control", MODBUS_CONTROL_CODES[fc]
        else:
            category, fc_name = "unknown", f"function {fc}"

        attrs: Dict[str, Any] = {
            "encrypted": False,       # Modbus/TCP has no transport security
            "unit": str(unit),
            "fc": str(fc),
            "fc_name": fc_name,
            "category": category,
            "stream": stream,
            "trans_id": one(layers, "mbtcp_trans_id") or "",
            "reference": one(layers, "modbus_reference_num") or "",
        }
        if exception is not None:
            attrs["exception"] = str(exception)
            attrs["exception_name"] = _MODBUS_EXCEPTIONS.get(
                exception, f"code {exception}"
            )

        # TRANSACTION ID. Unlike HTTP, Modbus carries its own: the master
        # sets `mbtcp.trans_id` and the slave echoes it, so both sides of a
        # pair agree without needing Wireshark's frame cross-reference. That
        # matters because `request_frame` is absent on exceptions, and a
        # frame-based key would leave every exception unpaired.
        #
        # Caveat: trans_id is 16-bit and masters may reuse it over a long
        # capture, which would merge two transactions into one group. Real
        # masters increment, so this is a bounded risk rather than a silent
        # one.
        trans_id = attrs["trans_id"] or str(frame_number)
        attrs["txn"] = f"{stream}:{trans_id}"

        if not is_request:
            if request_frame is not None:
                attrs["request_frame"] = str(request_frame)
            elapsed = one(layers, "modbus_response_time")
            if elapsed is not None:
                try:
                    attrs["elapsed_s"] = float(elapsed)
                except ValueError:
                    pass

        wire = as_int(one(layers, "frame_len"))

        return Observation(
            ts=float(one(layers, "frame_time_epoch") or 0.0),
            channel=Channel(
                domain="modbus",
                dims={"proto": "modbus"},
                initiator=Entity("ip", master),
                responder=Entity("ip", plc),
            ),
            direction=Direction.EGRESS if is_request else Direction.INGRESS,
            # Modbus PDUs are tiny and near-constant in size, so payload
            # length carries almost no signal; the useful quantities are
            # cadence, function code and unit id.
            size=wire or 0,
            kind="modbus_request" if is_request else "modbus_response",
            wire_size=wire,
            attrs=attrs,
            locus=Locus(source=source, frames=(frame_number,),
                        stream=as_int(stream)),
        )


# --------------------------------------------------------------------------
# dnp3
# --------------------------------------------------------------------------


DNP3_PORT = 20000

#: DNP3 application function codes that act on the physical process or on
#: the device itself. SELECT/OPERATE is the two-step control sequence;
#: DIRECT_OPERATE does it in one message.
DNP3_CONTROL_CODES = {
    2: ("write", "WRITE"),
    3: ("select", "SELECT"),
    4: ("operate", "OPERATE"),
    5: ("operate", "DIRECT_OPERATE"),
    6: ("operate", "DIRECT_OPERATE_NR"),
    13: ("restart", "COLD_RESTART"),
    14: ("restart", "WARM_RESTART"),
    18: ("restart", "STOP_APPL"),
    # Disabling unsolicited reporting blinds the real master without
    # touching the process — a denial of VIEW rather than of control, and
    # commonly a precursor.
    21: ("suppress", "DISABLE_UNSOLICITED"),
    20: ("suppress", "ENABLE_UNSOLICITED"),
}
#: Functions that only observe. CONFIRM is protocol bookkeeping.
DNP3_READ_CODES = {
    0: "CONFIRM",
    1: "READ",
    7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR",
    9: "FREEZE_CLEAR",
    22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE",
}
DNP3_RESPONSE_CODES = {129: "RESPONSE", 130: "UNSOLICITED_RESPONSE"}


class Dnp3Profile(TsharkProfile):
    """DNP3 (IEEE 1815) application-layer transactions.

    THE SECOND DOMAIN ONBOARDED THE CHEAP WAY, and it needed no new
    mathematics either — but it is a better test than Modbus because DNP3 is
    genuinely hard to parse. The link layer carries a CRC over its header
    and another after every 16-octet block of user data, so a fabricated
    frame with wrong CRCs dissects as malformed and never reaches the
    application layer. Delegating to Wireshark means none of that is this
    file's problem.

    CHANNEL GRANULARITY, same lesson as Modbus and DNS before it: `dims` is
    `{"proto": "dnp3"}` only. Function code and the DNP3 link addresses live
    in `attrs`, so `Fanout` can count them — address and function sweeps are
    the enumeration signature, and putting either in `dims` would make it
    uncountable.

    Identity is the (master IP, outstation IP) pair, so `rarity.novel`
    answers "a host that has never spoken DNP3 to this outstation just
    issued a control command".
    """

    domain = "dnp3"
    display_filter = "dnp3"
    fields = _COMMON_FIELDS + (
        "frame.len",
        "dnp3.src", "dnp3.dst",
        "dnp3.ctl.prifunc", "dnp3.ctl.dir", "dnp3.ctl.prm",
        "dnp3.al.func", "dnp3.al.seq", "dnp3.al.uns",
        "dnp3.al.iin",
        "dnp3.al.iin.rst", "dnp3.al.iin.dt", "dnp3.al.iin.fcni",
        "dnp3.al.iin.obju", "dnp3.al.iin.pioor", "dnp3.al.iin.ebo",
        "dnp3.al.obj",
    )

    def __init__(self) -> None:
        #: stream -> (wrap count, last request sequence). The DNP3
        #: application sequence is 4 bits; see the txn note in `build`.
        self._wrap: Dict[str, Tuple[int, int]] = {}

    def build(self, layers, source, retain_payloads):
        function = as_int(one(layers, "dnp3_al_func"))
        if function is None:
            return None

        stream = one(layers, "tcp_stream") or "-"
        frame_number = as_int(one(layers, "frame_number"), 0) or 0

        # A response is identified by its application function code, which is
        # unambiguous in DNP3 — 129 and 130 are responses and nothing else
        # is. No need for the port fallback Modbus required.
        is_response = function in DNP3_RESPONSE_CODES

        src = one(layers, "ip_src") or "?"
        dst = one(layers, "ip_dst") or "?"
        master, outstation = (dst, src) if is_response else (src, dst)

        if function in DNP3_CONTROL_CODES:
            category, name = DNP3_CONTROL_CODES[function]
        elif function in DNP3_RESPONSE_CODES:
            category, name = "response", DNP3_RESPONSE_CODES[function]
        elif function in DNP3_READ_CODES:
            category, name = "read", DNP3_READ_CODES[function]
        else:
            category, name = "unknown", f"function {function}"

        attrs: Dict[str, Any] = {
            "encrypted": False,       # DNP3 over TCP has no transport security
            "fc": str(function),
            "fc_name": name,
            "category": category,
            "link_src": one(layers, "dnp3_src") or "",
            "link_dst": one(layers, "dnp3_dst") or "",
            "stream": stream,
            "unsolicited": one(layers, "dnp3_al_uns") or "",
        }

        iin = one(layers, "dnp3_al_iin")
        if iin:
            attrs["iin"] = iin
            # Internal Indications worth naming. `rst` means the device has
            # restarted, which is how a restart attack shows up in traffic
            # the attacker did not send.
            flags = [
                label for field, label in (
                    ("dnp3_al_iin_rst", "device restart"),
                    ("dnp3_al_iin_dt", "device trouble"),
                    ("dnp3_al_iin_fcni", "function not implemented"),
                    ("dnp3_al_iin_obju", "requested objects unknown"),
                    ("dnp3_al_iin_pioor", "parameter out of range"),
                    ("dnp3_al_iin_ebo", "event buffer overflow"),
                )
                if one(layers, field) in ("1", "True")
            ]
            if flags:
                attrs["iin_flags"] = ", ".join(flags)

        # DNP3 carries an application sequence number that both sides echo,
        # which pairs a response to its request the way `mbtcp.trans_id`
        # does for Modbus — but it is only FOUR BITS and wraps at 16. A
        # `stream:seq` key therefore collapses unrelated exchanges: 40 poll
        # cycles folded into 16 groups of five, so `group_by("txn")` returned
        # ten-observation "transactions". A wrap counter makes the key
        # unique for as long as the connection lasts.
        sequence = as_int(one(layers, "dnp3_al_seq"))
        if sequence is None:
            attrs["txn"] = f"{stream}:f{frame_number}"
        else:
            wrap, last = self._wrap.get(stream, (0, -1))
            if not is_response:
                if sequence <= last:
                    wrap += 1
                self._wrap[stream] = (wrap, sequence)
            attrs["txn"] = f"{stream}:{wrap}:{sequence}"

        wire = as_int(one(layers, "frame_len"))

        return Observation(
            ts=float(one(layers, "frame_time_epoch") or 0.0),
            channel=Channel(
                domain="dnp3",
                dims={"proto": "dnp3"},
                initiator=Entity("ip", master),
                responder=Entity("ip", outstation),
            ),
            direction=Direction.INGRESS if is_response else Direction.EGRESS,
            size=wire or 0,
            kind="dnp3_response" if is_response else "dnp3_request",
            wire_size=wire,
            attrs=attrs,
            locus=Locus(source=source, frames=(frame_number,),
                        stream=as_int(stream)),
        )


_MODBUS_EXCEPTIONS = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge",
    0x06: "Server Device Busy",
    0x08: "Memory Parity Error",
    0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Device Failed To Respond",
}


# --------------------------------------------------------------------------
# the source
# --------------------------------------------------------------------------


class TsharkSource(CaptureSource):
    """Read a capture through tshark, using a profile.

    Streams tshark's stdout rather than buffering it, so a multi-gigabyte
    capture does not have to fit in memory.
    """

    def __init__(
        self,
        path: Path | str,
        profile: Optional[TsharkProfile] = None,
        keylog: Optional[Path | str] = None,
        retain_payloads: bool = True,
        tshark: str = "tshark",
    ):
        self.path = Path(path)
        self.profile = profile or HttpProfile()
        self.domain = self.profile.domain
        self.keylog = Path(keylog) if keylog else None
        # Defaults to TRUE here, unlike the native reader: a content
        # inspector with no body has nothing to inspect, and this source
        # exists for content analysis. Redaction on output is what keeps
        # that safe.
        self.retain_payloads = retain_payloads
        self.tshark = tshark
        self._proc: Optional[subprocess.Popen] = None
        #: profile fields this tshark build does not know; reported, not fatal
        self.dropped_fields: Tuple[str, ...] = ()
        self.stats = {"frames": 0, "observations": 0, "skipped": 0}

    def command(self) -> List[str]:
        cmd = [self.tshark, "-r", str(self.path), "-T", "ek", "-n"]
        if self.keylog:
            # tshark decrypts with the keylog; nothing here touches crypto.
            cmd += ["-o", f"tls.keylog_file:{self.keylog}"]
        if self.profile.display_filter:
            cmd += ["-Y", self.profile.display_filter]
        for field in self.usable_fields():
            cmd += ["-e", field]
        return cmd

    def usable_fields(self) -> List[str]:
        """Profile fields this tshark actually knows about."""
        known = known_fields(self.tshark)
        if not known:
            return list(self.profile.fields)
        usable, dropped = [], []
        for field in self.profile.fields:
            (usable if field in known else dropped).append(field)
        self.dropped_fields = tuple(dropped)
        return usable

    def observations(self) -> Iterator[Observation]:
        if shutil.which(self.tshark) is None:
            raise TsharkUnavailable(
                f"{self.tshark} not found on PATH. The native reader "
                "(capture/pcap.py) needs no external tools but cannot "
                "decrypt TLS or dissect HTTP."
            )
        if not self.path.exists():
            raise FileNotFoundError(self.path)
        if self.keylog and not self.keylog.exists():
            raise FileNotFoundError(f"keylog not found: {self.keylog}")

        self._proc = subprocess.Popen(
            self.command(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self._proc.stdout is not None

        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            layers = record.get("layers")
            if not layers:
                continue  # the alternating "index" line
            self.stats["frames"] += 1

            obs = self.profile.build(layers, self.path.name, self.retain_payloads)
            if obs is None:
                self.stats["skipped"] += 1
                continue
            self.stats["observations"] += 1
            yield obs

        self._drain()

    def _drain(self) -> None:
        if self._proc is None:
            return
        stderr = self._proc.stderr.read() if self._proc.stderr else ""
        code = self._proc.wait()
        self._proc = None
        if code != 0:
            # Surface it. A tshark that failed produces zero observations,
            # which is indistinguishable from a clean capture unless the
            # error is raised.
            raise RuntimeError(
                f"tshark exited {code}: {stderr.strip()[:500] or 'no output'}"
            )

    def close(self) -> None:
        if self._proc is not None:
            self._proc.kill()
            self._proc = None
