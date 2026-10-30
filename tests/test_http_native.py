"""Native cleartext HTTP/1.x, with no tshark.

THE LOAD-BEARING TEST HERE IS `test_native_attrs_satisfy_every_inspector`.
The point of this parser is not that it reads HTTP — it is that it emits the
SAME attribute names as `capture/tshark.py`'s HttpProfile, so every existing
inspector and rule works against it unchanged. If an attribute is renamed or
dropped, an inspector reads `attrs.get("set_cookie")`, finds nothing, and
reports no problem — which is indistinguishable from a clean response. That
failure is silent, which is why it is asserted rather than assumed.

The framing tests cover the cases that make a naive parser stall or
desynchronise: a body split across segments, keep-alive putting several
transactions on one connection, chunked encoding, and the bodiless statuses
(204/304) whose Content-Length describes a body that is not there. A parser
that waits for those bytes hangs, and on a keep-alive connection every later
response is lost with it.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from capture.base import group_into_series
from capture.http1 import HttpStream, looks_like_http
from capture.httpobs import HttpTracker
from capture.pcap import PcapSource
from capture.pcapfile import LINKTYPE_ETHERNET
from core.model import Context
from core.score import run as score_run


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------


def _feed(stream: HttpStream, from_client: bool, *chunks: bytes):
    out = []
    for index, chunk in enumerate(chunks):
        out.extend(stream.feed(from_client, chunk, index + 1))
    return out


def test_request_and_response_are_parsed():
    stream = HttpStream()
    requests = _feed(
        stream, True,
        b"GET /a?x=1 HTTP/1.1\r\nHost: shop.test\r\nCookie: s=1\r\n\r\n",
    )
    responses = _feed(
        stream, False,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        b"Set-Cookie: a=1\r\n\r\nhello",
    )

    assert len(requests) == 1, requests
    assert requests[0].method == "GET"
    assert requests[0].target == "/a?x=1"
    assert requests[0].headers["host"] == "shop.test"

    assert len(responses) == 1, responses
    assert responses[0].status == "200"
    assert responses[0].body == b"hello"


def test_message_split_across_segments_is_reassembled():
    """Headers and body arrive in pieces; nothing may be emitted until the
    message is whole, and then exactly once."""
    stream = HttpStream()
    whole = (b"POST /submit HTTP/1.1\r\nHost: shop.test\r\n"
             b"Content-Length: 11\r\n\r\nhello world")
    pieces = [whole[i:i + 7] for i in range(0, len(whole), 7)]
    assert len(pieces) > 3

    messages = _feed(stream, True, *pieces)
    assert len(messages) == 1, messages
    assert messages[0].body == b"hello world", messages[0].body
    assert messages[0].method == "POST"


def test_keepalive_yields_several_transactions_on_one_connection():
    """Several transactions share one connection, which is exactly why
    `stream` is a CONNECTION id and `txn` is the transaction id."""
    stream = HttpStream()
    requests = _feed(
        stream, True,
        b"GET /one HTTP/1.1\r\nHost: s.test\r\n\r\n"
        b"GET /two HTTP/1.1\r\nHost: s.test\r\n\r\n"
        b"GET /three HTTP/1.1\r\nHost: s.test\r\n\r\n",
    )
    assert [m.target for m in requests] == ["/one", "/two", "/three"], requests

    responses = _feed(
        stream, False,
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nb"
        b"HTTP/1.1 500 Oops\r\nContent-Length: 1\r\n\r\nc",
    )
    assert [m.status for m in responses] == ["200", "404", "500"], responses


def test_chunked_body_is_decoded():
    stream = HttpStream()
    responses = _feed(
        stream, False,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    assert len(responses) == 1, responses
    assert responses[0].body == b"hello world", responses[0].body


def test_chunked_body_split_across_segments():
    stream = HttpStream()
    messages = _feed(
        stream, False,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
        b"lo\r\n6\r\n wor",
        b"ld\r\n0\r\n\r\n",
    )
    assert len(messages) == 1, messages
    assert messages[0].body == b"hello world", messages[0].body


def test_bodiless_statuses_do_not_stall_the_connection():
    """A 304 may carry Content-Length describing the body it WOULD have had.
    Waiting for those bytes hangs the parser, and on a keep-alive connection
    every later response is then lost too."""
    stream = HttpStream()
    messages = _feed(
        stream, False,
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    )
    assert [m.status for m in messages] == ["304", "200"], messages
    assert messages[1].body == b"ok"


def test_repeated_set_cookie_headers_are_all_kept():
    """A response setting three cookies collapses to one in a flat dict, and
    the cookie inspector would judge two of them as though they did not
    exist."""
    stream = HttpStream()
    messages = _feed(
        stream, False,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
        b"Set-Cookie: a=1; Secure\r\n"
        b"Set-Cookie: b=2\r\n"
        b"Set-Cookie: c=3; HttpOnly\r\n\r\n",
    )
    assert len(messages) == 1
    assert messages[0].repeated["set-cookie"] == (
        "a=1; Secure", "b=2", "c=3; HttpOnly"
    ), messages[0].repeated


def test_response_with_no_length_emits_headers_rather_than_blocking():
    """Length indeterminate — a body that runs until the connection closes.
    The headers are most of the value and waiting for a close that may never
    appear in the capture would discard them entirely."""
    stream = HttpStream()
    messages = _feed(
        stream, False,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
    )
    assert len(messages) == 1, messages
    assert messages[0].body_unknown, messages[0]
    assert messages[0].body == b"<html>"


def test_non_http_traffic_is_rejected_not_guessed():
    assert not looks_like_http(b"\x16\x03\x01\x02\x00\x01")
    assert not looks_like_http(b"SSH-2.0-OpenSSH_9.0")
    assert not looks_like_http(b"")
    assert looks_like_http(b"GET / HTTP/1.1\r\n")
    assert looks_like_http(b"HTTP/1.1 200 OK\r\n")

    stream = HttpStream()
    assert _feed(stream, True, b"\x00\x01\x02\x03" * 10) == []


def test_header_flood_is_capped_and_stops_the_side():
    """A sender that never terminates its headers must not be able to grow a
    buffer until the machine dies."""
    stream = HttpStream()
    # 64 kB with no terminator, against a 32 kB cap.
    assert _feed(stream, True, b"GET / HTTP/1.1\r\nX: " + b"a" * 65536) == []
    # And the side is now stopped rather than retrying forever.
    assert _feed(stream, True, b"\r\n\r\n") == []


def test_large_body_is_sampled_and_marked_truncated():
    stream = HttpStream()
    body = b"x" * 40000
    messages = _feed(
        stream, False,
        b"HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n" + body,
    )
    assert len(messages) == 1, messages
    assert messages[0].body_truncated, messages[0]
    assert 0 < len(messages[0].body) <= 16 * 1024


# --------------------------------------------------------------------------
# the observation contract
# --------------------------------------------------------------------------


def _exchange(tracker: HttpTracker, request: bytes, response: bytes,
              stream: int = 0, ts: float = 1_700_000_000.0):
    out = tracker.feed(stream, True, request, 1, ts,
                       "10.0.0.5", "203.0.113.9", 80)
    out += tracker.feed(stream, False, response, 2, ts + 0.25,
                        "10.0.0.5", "203.0.113.9", 80)
    return out


def test_native_attrs_satisfy_every_inspector():
    """THE LOAD-BEARING TEST. Attribute names are a contract with
    `capture/tshark.py`; a rename breaks every inspector silently."""
    tracker = HttpTracker("t.pcap")
    observations = _exchange(
        tracker,
        b"GET /account?token=abc HTTP/1.1\r\nHost: shop.test\r\n"
        b"Authorization: Bearer xyz\r\nCookie: sid=1\r\n"
        b"Origin: https://evil.test\r\nReferer: https://shop.test/\r\n"
        b"User-Agent: curl/8\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2\r\nSet-Cookie: sid=2\r\n"
        b"Access-Control-Allow-Origin: *\r\n"
        b"Location: /next\r\n\r\n{}",
    )
    assert len(observations) == 2, observations
    request, response = observations

    for key in ("encrypted", "decrypted", "host", "path", "headers", "stream",
                "http2_stream", "txn", "method", "full_uri", "query",
                "params", "authorization", "cookie", "referer", "user_agent",
                "body_text"):
        assert key in request.attrs, f"request missing {key}"

    for key in ("encrypted", "decrypted", "host", "path", "headers", "stream",
                "http2_stream", "txn", "status", "content_type", "set_cookie",
                "location", "request_origin", "request_path", "body_text",
                "connection_warm_up", "elapsed_s", "request_frame"):
        assert key in response.attrs, f"response missing {key}"

    assert request.attrs["method"] == "GET"
    assert request.attrs["path"] == "/account"
    assert request.attrs["query"] == "token=abc"
    assert request.attrs["params"] == ("token",)
    assert request.attrs["full_uri"] == "http://shop.test/account?token=abc"
    assert request.attrs["authorization"] == "Bearer xyz"

    assert response.attrs["status"] == "200"
    assert response.attrs["set_cookie"] == ["sid=2"]
    # The response's Allow-Origin can only be judged against the REQUEST's
    # Origin, and those are two separate messages.
    assert response.attrs["request_origin"] == "https://evil.test"
    assert response.attrs["headers"]["access-control-allow-origin"] == "*"
    assert response.attrs["request_path"] == "/account"


def test_channel_dims_match_the_tshark_profile():
    """dims are {scheme, host} — the channel is a HOST, with method/path in
    attrs. Changing this would split the inventory and the fanout counts."""
    tracker = HttpTracker("t.pcap")
    observations = _exchange(
        tracker,
        b"GET /x HTTP/1.1\r\nHost: shop.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    for obs in observations:
        assert obs.channel.domain == "http"
        assert obs.channel.dims == {"scheme": "http", "host": "shop.test"}


def test_txn_pairs_a_response_to_its_request():
    tracker = HttpTracker("t.pcap")
    request, response = _exchange(
        tracker,
        b"GET /x HTTP/1.1\r\nHost: s.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    assert request.attrs["txn"] == response.attrs["txn"], (
        request.attrs["txn"], response.attrs["txn"]
    )
    assert abs(response.attrs["elapsed_s"] - 0.25) < 1e-6


def test_first_response_on_a_connection_is_marked_warm_up():
    """TCP slow start and a cold server make the first response
    systematically slower for reasons unrelated to the application. Two of
    them in a sample of ten fabricate a latency cluster — a false positive
    this project has already shipped once."""
    tracker = HttpTracker("t.pcap")
    first = _exchange(
        tracker,
        b"GET /a HTTP/1.1\r\nHost: s.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    second = _exchange(
        tracker,
        b"GET /b HTTP/1.1\r\nHost: s.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    assert first[1].attrs["connection_warm_up"] is True
    assert second[1].attrs["connection_warm_up"] is False


def test_request_size_counts_headers_not_just_body():
    """Body alone would make a header-heavy request look empty to
    `Asymmetry` — a 4 kB cookie jar is not a zero-byte message."""
    tracker = HttpTracker("t.pcap")
    request, _response = _exchange(
        tracker,
        b"GET /x HTTP/1.1\r\nHost: s.test\r\nCookie: " + b"a" * 2000
        + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    assert request.size > 2000, request.size


def test_absolute_form_target_through_a_proxy():
    """A proxy request carries the whole URL as the target. Taking the path
    off it naively yields the full URL as the path, and the inventory then
    templates nonsense."""
    tracker = HttpTracker("t.pcap")
    request, _ = _exchange(
        tracker,
        b"GET http://shop.test/a/b?c=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    assert request.attrs["path"] == "/a/b", request.attrs["path"]
    assert request.attrs["query"] == "c=1"


# --------------------------------------------------------------------------
# end to end, through a real pcap, and into the inspectors
# --------------------------------------------------------------------------


def _tcp(src, dst, sport, dport, flags, payload=b"") -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                      1024, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     bytes(int(o) for o in src.split(".")),
                     bytes(int(o) for o in dst.split(".")))
    return b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x00" + ip + tcp


def _write(path: Path, frames) -> None:
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, LINKTYPE_ETHERNET))
        for index, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", 1_700_000_000 + index,
                                     index * 100000, len(frame), len(frame)))
            handle.write(frame)


def _capture(frames):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "http.pcap"
        _write(path, frames)
        source = PcapSource(path)
        return list(source.observations()), source.stats


def test_http_observations_come_out_of_a_real_pcap():
    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _tcp(client, server, 4444, 80, 0x02),
        _tcp(server, client, 80, 4444, 0x12),
        _tcp(client, server, 4444, 80, 0x18,
             b"GET /login HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
        _tcp(server, client, 80, 4444, 0x18,
             b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
             b"Set-Cookie: sid=abc\r\n\r\nhi"),
    ]
    observations, stats = _capture(frames)

    http = [o for o in observations if o.channel.domain == "http"]
    assert len(http) == 2, [o.kind for o in observations]
    assert stats["http"] == 2, stats
    assert {o.kind for o in http} == {"http_request", "http_response"}
    assert http[0].attrs["host"] == "shop.test"
    assert http[1].attrs["set_cookie"] == ["sid=abc"]


def test_net_and_http_both_describe_the_connection():
    """Emitted in addition to the net burst, not instead of it: the two
    describe the same bytes at different layers and answer different
    questions."""
    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _tcp(client, server, 4445, 80, 0x02),
        _tcp(server, client, 80, 4445, 0x12),
        _tcp(client, server, 4445, 80, 0x18,
             b"GET / HTTP/1.1\r\nHost: s.test\r\n\r\n"),
        _tcp(server, client, 80, 4445, 0x18,
             b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    ]
    observations, _stats = _capture(frames)
    domains = {o.channel.domain for o in observations}
    assert domains == {"net", "http"}, domains


def test_tls_flow_is_not_parsed_as_http():
    """A TLS ClientHello must not be fed to the HTTP parser."""
    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _tcp(client, server, 4446, 443, 0x02),
        _tcp(server, client, 443, 4446, 0x12),
        _tcp(client, server, 4446, 443, 0x18,
             b"\x16\x03\x01\x00\x10\x01\x00\x00\x0c" + b"\x00" * 7),
    ]
    observations, _stats = _capture(frames)
    assert not [o for o in observations if o.channel.domain == "http"]


def test_native_http_reaches_the_inspectors_and_produces_a_finding():
    """The end the whole exercise is for: content analysis with no tshark.

    An insecure session cookie over cleartext HTTP is what the auth
    inspectors exist to catch, and this asserts the native path delivers
    evidence they can act on.
    """
    from ontology import ONTOLOGIES

    client, server = "10.0.0.5", "203.0.113.9"
    frames = [
        _tcp(client, server, 4447, 80, 0x02),
        _tcp(server, client, 80, 4447, 0x12),
    ]
    # Several transactions so the inspectors have a sample to work with.
    for index in range(6):
        frames.append(_tcp(
            client, server, 4447, 80, 0x18,
            f"GET /app/{index} HTTP/1.1\r\nHost: shop.test\r\n"
            f"Cookie: SESSIONID=abc{index}\r\n\r\n".encode(),
        ))
        frames.append(_tcp(
            server, client, 80, 4447, 0x18,
            f"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            f"Set-Cookie: SESSIONID=abc{index}; Path=/\r\n\r\nhi".encode(),
        ))

    observations, _stats = _capture(frames)
    http = [o for o in observations if o.channel.domain == "http"]
    assert len(http) == 12, len(http)

    series = list(group_into_series(http, min_observations=2))
    assert series, "no http series produced"

    ctx = Context(now=1_700_001_000.0, mode="assisted")
    findings, evidences = score_run(series, ONTOLOGIES, ctx)

    inspected = [i.name for e in evidences for i in e.inspections]
    assert inspected, "no inspector produced evidence from native HTTP"
    # A cookie with no Secure and no HttpOnly is the specific defect here.
    assert any("cookie" in name for name in inspected), inspected


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name_, fn in tests:
        try:
            fn()
            print(f"  ok    {name_}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name_}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
