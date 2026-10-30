"""HTTP/1.x read straight from the wire, with no tshark.

WHY. The HTTP content analysis — cookie flags, JWTs, CORS, secrets in
response bodies, credentials in URLs — needed `tshark` on PATH, which is a
real dependency for a tool whose pitch is `semantiq.py read foo.pcap` on a
laptop. And it was never necessary for CLEARTEXT HTTP: port-80 traffic in a
capture needs no keys and no dissector, only a parser. So this reads it
directly.

IT EMITS THE SAME OBSERVATION SHAPE AS `capture/tshark.py`'s HttpProfile —
same `dims`, same attribute names, same conventions for `txn`,
`connection_warm_up` and `elapsed_s`. That is the whole design constraint
and the whole payoff: every inspector in `inspectors/` and every rule in
`ontology/http.py` works against this with no changes. A second HTTP source
that invented its own attribute names would have needed a second set of
inspectors, and the two would have drifted.

WHERE IT IS WEAKER THAN TSHARK, stated plainly because the difference
matters for one specific analysis:

  Request/response pairing here is FIFO per connection. Wireshark's
  `http.request_in` is computed by a dissector that tracks pipelining
  properly; this assumes responses come back in request order, which is true
  for HTTP/1.1 keep-alive in practice and NOT guaranteed under pipelining.
  Pipelining is rare — browsers abandoned it — but where it occurs, `txn`
  and therefore `elapsed_s` can mis-pair. The response-time oracle is the
  analysis that depends on this, so prefer `--http` with tshark when latency
  clustering is the question.

  HTTP/2 is not parsed. It is binary, almost always inside TLS, and would
  need HPACK state. `http2_stream` is emitted empty to keep the attribute
  contract identical.

BOUNDED BY CONSTRUCTION. Headers are buffered to a cap and bodies to a
smaller one, per direction per connection, because a capture is adversarial
input: a server that never sends a header terminator must not be able to
grow a buffer until the analyst's machine dies. Truncation is recorded, never
silent.
"""

from __future__ import annotations

from typing import Dict, List, NamedTuple, Optional, Tuple

__all__ = [
    "HttpMessage",
    "HttpStream",
    "METHODS",
    "looks_like_http",
    "MAX_HEADER_BYTES",
    "MAX_BODY_BYTES",
]

#: Methods recognised on a request line. CONNECT is included so a proxy
#: tunnel is identified as HTTP rather than left as anonymous bytes.
METHODS = frozenset({
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE",
    "CONNECT",
})

#: Caps, per direction per connection. Headers get the larger budget because
#: a request with a long cookie jar is normal; bodies are sampled, since the
#: inspectors look for secrets and markers near the start rather than
#: needing the whole payload.
MAX_HEADER_BYTES = 32 * 1024
MAX_BODY_BYTES = 16 * 1024

#: Statuses that carry no body regardless of headers (RFC 9110). Waiting for
#: a body on a 304 stalls the parser until the connection closes, and the
#: next response on a keep-alive connection is then never parsed at all.
_BODILESS_STATUS = frozenset({204, 304})

_TERMINATOR = b"\r\n\r\n"
#: Some servers, and plenty of embedded ones, use bare LF.
_TERMINATOR_LF = b"\n\n"


class HttpMessage(NamedTuple):
    is_request: bool
    method: str
    target: str
    version: str
    status: str
    reason: str
    headers: Dict[str, str]
    #: Header names appearing more than once, kept in order. `set-cookie` is
    #: the one that matters: a response setting three cookies collapses to
    #: one in a flat dict, and the cookie inspector would judge two of them
    #: as though they did not exist.
    repeated: Dict[str, Tuple[str, ...]]
    body: bytes
    body_truncated: bool
    #: True when the message's length could not be determined — no
    #: Content-Length, not chunked — so the body shown may be partial.
    body_unknown: bool
    frame: int


def looks_like_http(data: bytes) -> bool:
    """Cheap test for the first bytes of a connection."""
    if data.startswith(b"HTTP/"):
        return True
    head = data[:8].split(b" ", 1)[0]
    try:
        return head.decode("ascii") in METHODS
    except UnicodeDecodeError:
        return False


class _Side:
    """Buffered bytes for one direction of one connection."""

    __slots__ = ("buffer", "frame", "overflow", "stopped")

    def __init__(self) -> None:
        self.buffer = bytearray()
        #: Frame the current message started in, for the Locus.
        self.frame = 0
        self.overflow = False
        #: Set when this direction is no longer parseable — a malformed
        #: message resynchronises nothing, so the honest move is to stop
        #: rather than emit guesses from a desynchronised stream.
        self.stopped = False


class HttpStream:
    """HTTP/1.x message extraction for one TCP connection.

    Separate buffers per direction, because requests and responses are
    independent byte streams that happen to share a connection, and a
    pipelined or overlapped exchange interleaves them.
    """

    def __init__(self) -> None:
        self._up = _Side()     # client -> server
        self._down = _Side()   # server -> client
        #: Requests awaiting a response, FIFO. See the module docstring for
        #: why this is weaker than Wireshark's pairing.
        self.pending: List[Tuple[int, float, str]] = []
        self.answered = False

    def feed(self, from_client: bool, data: bytes, frame: int) -> List[HttpMessage]:
        side = self._up if from_client else self._down
        if side.stopped or not data:
            return []

        if not side.buffer:
            side.frame = frame
        side.buffer += data

        messages: List[HttpMessage] = []
        while True:
            message = self._take(side, from_client)
            if message is None:
                break
            messages.append(message)
            if side.buffer:
                side.frame = frame
        return messages

    def _take(self, side: _Side, from_client: bool) -> Optional[HttpMessage]:
        """Pull one complete message off the front of the buffer."""
        buffer = side.buffer
        if not buffer:
            return None

        split = buffer.find(_TERMINATOR)
        gap = 4
        if split < 0:
            split = buffer.find(_TERMINATOR_LF)
            gap = 2
        if split < 0:
            if len(buffer) > MAX_HEADER_BYTES:
                # No terminator inside the budget: either not HTTP, or a
                # stream this parser cannot follow. Either way, stop.
                side.overflow = True
                side.stopped = True
                side.buffer = bytearray()
            return None

        head = bytes(buffer[:split])
        body_start = split + gap

        parsed = _parse_head(head, from_client)
        if parsed is None:
            side.stopped = True
            side.buffer = bytearray()
            return None
        start_line, headers, repeated = parsed

        length, chunked = _body_length(headers, start_line, from_client)
        available = len(buffer) - body_start

        body = b""
        truncated = False
        unknown = False

        if chunked:
            decoded, consumed, complete = _dechunk(
                bytes(buffer[body_start:])
            )
            if not complete and available <= MAX_BODY_BYTES:
                return None  # wait for more chunks
            body = decoded[:MAX_BODY_BYTES]
            truncated = len(decoded) > MAX_BODY_BYTES or not complete
            body_end = body_start + (consumed if complete
                                     else max(consumed, available))
        elif length is None:
            # Length indeterminate: a response that runs until the connection
            # closes. Emit the headers now with whatever body is present
            # rather than blocking — the headers are most of the value, and
            # waiting for a close that may never appear in the capture would
            # discard them entirely.
            body = bytes(buffer[body_start:body_start + MAX_BODY_BYTES])
            unknown = True
            truncated = available > MAX_BODY_BYTES
            body_end = len(buffer)
        else:
            if length > MAX_BODY_BYTES:
                if available < length:
                    # Cannot hold the whole thing anyway; take the sample and
                    # skip ahead only once the rest has gone past.
                    if available <= MAX_BODY_BYTES:
                        return None
                body = bytes(buffer[body_start:body_start + MAX_BODY_BYTES])
                truncated = True
                body_end = min(body_start + length, len(buffer))
            else:
                if available < length:
                    return None  # wait for the rest of the body
                body = bytes(buffer[body_start:body_start + length])
                body_end = body_start + length

        side.buffer = bytearray(buffer[body_end:])

        method, target, version, status, reason = start_line
        return HttpMessage(
            is_request=from_client,
            method=method,
            target=target,
            version=version,
            status=status,
            reason=reason,
            headers=headers,
            repeated=repeated,
            body=body,
            body_truncated=truncated,
            body_unknown=unknown,
            frame=side.frame,
        )


def _parse_head(
    head: bytes, from_client: bool
) -> Optional[Tuple[Tuple[str, str, str, str, str], Dict[str, str],
                    Dict[str, Tuple[str, ...]]]]:
    """Start line and headers. None if this is not an HTTP message."""
    try:
        text = head.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None

    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0]:
        return None

    first = lines[0].split(" ")
    method = target = version = status = reason = ""

    if from_client:
        if len(first) < 2 or first[0] not in METHODS:
            return None
        method, target = first[0], first[1]
        version = first[2] if len(first) > 2 else "HTTP/1.1"
    else:
        if len(first) < 2 or not first[0].startswith("HTTP/"):
            return None
        version, status = first[0], first[1]
        reason = " ".join(first[2:])
        if not status.isdigit():
            return None

    headers: Dict[str, str] = {}
    repeated: Dict[str, List[str]] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not key:
            continue
        if key in headers:
            repeated.setdefault(key, [headers[key]]).append(value)
        else:
            headers[key] = value
        if len(headers) > 128:
            break

    return (
        (method, target, version, status, reason),
        headers,
        {key: tuple(values) for key, values in repeated.items()},
    )


def _body_length(
    headers: Dict[str, str],
    start_line: Tuple[str, str, str, str, str],
    from_client: bool,
) -> Tuple[Optional[int], bool]:
    """(content_length, is_chunked). A length of 0 means no body.

    The bodiless cases are not an optimisation. A 304 or a HEAD response with
    a Content-Length header describes the body the request WOULD have had;
    waiting for those bytes stalls the parser forever, and on a keep-alive
    connection every later response is then lost too.
    """
    method, _target, _version, status, _reason = start_line

    if "chunked" in headers.get("transfer-encoding", "").lower():
        return None, True

    if not from_client:
        code = int(status) if status.isdigit() else 0
        if code in _BODILESS_STATUS or 100 <= code < 200:
            return 0, False

    raw = headers.get("content-length")
    if raw is not None:
        try:
            # A negative or absurd value is a malformed header, not a length.
            value = int(raw.split(",")[0].strip())
            return (value if value >= 0 else 0), False
        except ValueError:
            return 0, False

    if from_client:
        # A request with no length and no chunking has no body. This is why
        # requests never block waiting for one.
        return 0, False
    return None, False


def _dechunk(data: bytes) -> Tuple[bytes, int, bool]:
    """Decode chunked transfer encoding.

    Returns (body, bytes_consumed, complete). Stops at the terminating
    zero-length chunk, at the cap, or when the data runs out.
    """
    out = bytearray()
    pos = 0
    while pos < len(data):
        end = data.find(b"\r\n", pos)
        if end < 0:
            return bytes(out), pos, False
        header = data[pos:end].split(b";")[0].strip()
        try:
            size = int(header, 16)
        except ValueError:
            return bytes(out), pos, False
        pos = end + 2
        if size == 0:
            # Trailer section, then a final CRLF.
            closing = data.find(b"\r\n", pos)
            return bytes(out), (closing + 2 if closing >= 0 else pos), True
        if pos + size > len(data):
            out += data[pos:]
            return bytes(out), len(data), False
        out += data[pos:pos + size]
        pos += size + 2
        if len(out) > MAX_BODY_BYTES * 4:
            return bytes(out), pos, True
    return bytes(out), pos, False
