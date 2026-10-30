#!/usr/bin/env python3
"""Synthesise a real TLS 1.3 capture plus its keylog, with no sniffer.

Testing assisted mode needs a capture that genuinely decrypts, which normally
means live capture and interface permissions. This avoids both: a recording
relay sits between a real Python TLS client and a real Python TLS server,
copies ciphertext in both directions, and writes what it saw into a pcap with
correctly sequenced TCP headers. The client's `SSLContext.keylog_filename`
produces the matching NSS keylog.

The TLS is real — OpenSSL on both ends, real handshake, real AEAD — so
`tshark -o tls.keylog_file:...` decrypts it exactly as it would decrypt a
browser session. Nothing here touches a network interface.

Five exchanges across three hosts, carrying the defects the analyzers look
for. Each exchange is its own TLS session on its own TCP stream, so the
capture exercises multi-host correlation and not just one request:

    1  api.target-practice.test       profile read — cookies, CORS, secrets,
                                      JWT in Authorization, key in query
    2  api.target-practice.test       /v2/users/4417/orders — enumerable id
    3  api.target-practice.test       POST /v2/orders — parameter inventory
    4  analytics.thirdparty.test      THE LEAK: the same bearer token sent to
                                      an unrelated third-party host
    5  auth.target-practice.test      OAuth implicit flow, no PKCE, no state

    python3 tools/make_tls_pcap.py out/tls.pcap out/keys.log
"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CLIENT_IP = "10.1.1.50"

HOSTS = {
    "api.target-practice.test": "203.0.113.42",
    "analytics.thirdparty-metrics.test": "198.51.100.77",
    "auth.target-practice.test": "203.0.113.43",
}

# (timestamp, from_client, payload)
Chunk = Tuple[float, bool, bytes]


# --------------------------------------------------------------------------
# the exchanges
# --------------------------------------------------------------------------


def _jwt() -> str:
    """An HS256 JWT with no `exp` and sensitive claims.

    Hand-assembled rather than signed: the point is to exercise header and
    claim inspection, and a real signature would add a dependency for no
    test value.
    """
    def seg(obj) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = seg({"alg": "HS256", "typ": "JWT", "kid": "internal-signing-key-1"})
    claims = seg({
        "sub": "user-4417",
        "email": "victim@target-practice.test",
        "role": "admin",
        "iat": 1700000000,
        # no exp on purpose
    })
    return f"{header}.{claims}.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"


BEARER = _jwt()
# Fixture bait, assembled at runtime: a live-shaped token at rest in the
# source would trip every secret scanner pointed at this repository —
# including GitHub's push protection — forever. The inspector under test
# still receives the assembled value on the wire, which is what matters.
API_KEY = "sk_live_" + "8f3a2b1c9d4e5f6a7b8c9d0e"
STRIPE_KEY = "sk_live_" + "51HxQpLMNopQrStUvWxYz0123456789abcdef"
SESSION = "7f3a2b1c9d4e5f6a"


@dataclass
class Exchange:
    host: str
    request: bytes
    response: bytes


def _request(method: str, target: str, host: str, headers: Dict[str, str],
             body: bytes = b"") -> bytes:
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}",
             "User-Agent: semantiq-test/0.1"]
    if body:
        headers = dict(headers, **{"Content-Length": str(len(body))})
    lines += [f"{k}: {v}" for k, v in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _response(status: str, headers: Dict[str, str], body: bytes,
              set_cookies: Tuple[str, ...] = ()) -> bytes:
    lines = [f"HTTP/1.1 {status}", f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    lines += [f"Set-Cookie: {c}" for c in set_cookies]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


_PROFILE_BODY = json.dumps({
    "user": {"id": 4417, "email": "victim@target-practice.test", "role": "admin"},
    "internal": {
        "host": "api-internal-07.corp.target-practice.test",
        "upstream": "http://10.0.44.17:8080/v1",
    },
    "config": {
        "stripe_key": STRIPE_KEY,
        "aws_key": "AKIAIOSFODNN7EXAMPLE",
        "upload_bucket": "https://target-practice-uploads.s3.amazonaws.com/",
    },
    "next": "/v2/account/profile?user_id=4418",
}, indent=1).encode()


EXCHANGES: List[Exchange] = [
    # 1 — the kitchen sink: cookies, CORS reflection, secrets, JWT, key in URL
    Exchange(
        host="api.target-practice.test",
        request=_request(
            "GET", f"/v2/account/profile?api_key={API_KEY}&debug=true",
            "api.target-practice.test",
            {
                "Authorization": f"Bearer {BEARER}",
                "Cookie": f"session={SESSION}; tracking_id=abc123",
                "Origin": "https://evil.example",
                "Accept": "application/json",
            },
        ),
        response=_response(
            "200 OK",
            {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "https://evil.example",
                "Access-Control-Allow-Credentials": "true",
                "Server": "nginx/1.18.0 (Ubuntu)",
                "X-Powered-By": "Express",
                "X-RateLimit-Limit": "100",
            },
            _PROFILE_BODY,
            set_cookies=(
                f"session={SESSION}; Path=/; Domain=.target-practice.test",
                "csrf=9a8b7c6d; Path=/",
            ),
        ),
    ),
    # 2 — a numeric identifier in the path: inventory + enumeration candidate
    Exchange(
        host="api.target-practice.test",
        request=_request(
            "GET", "/v2/users/4417/orders?limit=20&offset=0",
            "api.target-practice.test",
            {"Authorization": f"Bearer {BEARER}", "Accept": "application/json"},
        ),
        response=_response(
            "200 OK", {"Content-Type": "application/json"},
            json.dumps({"orders": [{"id": 90211}, {"id": 90212}]}).encode(),
        ),
    ),
    # 3 — a write endpoint with body parameters
    Exchange(
        host="api.target-practice.test",
        request=_request(
            "POST", "/v2/orders", "api.target-practice.test",
            {
                "Authorization": f"Bearer {BEARER}",
                "Content-Type": "application/json",
            },
            body=json.dumps({"sku": "X-1", "qty": 2, "address_id": 551}).encode(),
        ),
        response=_response(
            "201 Created", {"Content-Type": "application/json"},
            json.dumps({"id": 90213, "status": "pending"}).encode(),
        ),
    ),
    # 4 — THE LEAK. Same bearer token, unrelated third-party host.
    Exchange(
        host="analytics.thirdparty-metrics.test",
        request=_request(
            "GET",
            f"/collect?uid=user-4417&email=victim%40target-practice.test&token={BEARER}",
            "analytics.thirdparty-metrics.test",
            {
                "Authorization": f"Bearer {BEARER}",
                "Referer": "https://api.target-practice.test/v2/account/profile",
            },
        ),
        response=_response("204 No Content", {}, b""),
    ),
    # 5 — OAuth implicit flow: token in fragment, no PKCE, no state
    Exchange(
        host="auth.target-practice.test",
        request=_request(
            "GET",
            "/oauth/authorize?response_type=token&client_id=web-app-1"
            "&redirect_uri=https%3A%2F%2Ftarget-practice.test%2Fcb"
            "&scope=profile+orders+admin",
            "auth.target-practice.test",
            {"Accept": "text/html"},
        ),
        response=_response(
            "302 Found",
            {"Location": "https://target-practice.test/cb#access_token="
                         f"{BEARER}&token_type=bearer"},
            b"",
        ),
    ),
]


# --------------------------------------------------------------------------
# recording relay
# --------------------------------------------------------------------------


def _self_signed(tmp: Path) -> Tuple[Path, Path]:
    """One cert with a SAN for every host the fixture uses."""
    cert, key = tmp / "cert.pem", tmp / "key.pem"
    sans = ",".join(f"DNS:{h}" for h in HOSTS)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=target-practice.test", "-addext", f"subjectAltName={sans}"],
        check=True, capture_output=True,
    )
    return cert, key


def _serve_once(listener: socket.socket, context: ssl.SSLContext,
                response: bytes) -> None:
    try:
        raw, _ = listener.accept()
        with context.wrap_socket(raw, server_side=True) as tls:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                request += chunk
            tls.sendall(response)
    except (ssl.SSLError, OSError):
        pass


def _relay_once(listener: socket.socket, upstream: Tuple[str, int],
                chunks: List[Chunk]) -> None:
    """Copy bytes both ways, recording each read with its direction and time.

    Reads are recorded as they arrive, so timestamps are real wire timings
    rather than invented ones — which matters because the burst assembler's
    gap rule is measured against exactly these.
    """
    downstream, _ = listener.accept()
    up = socket.create_connection(upstream)

    def pump(src: socket.socket, dst: socket.socket, from_client: bool) -> None:
        try:
            while True:
                data = src.recv(16384)
                if not data:
                    break
                chunks.append((time.time(), from_client, data))
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threads = [
        threading.Thread(target=pump, args=(downstream, up, True)),
        threading.Thread(target=pump, args=(up, downstream, False)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    downstream.close()
    up.close()


def _one_exchange(exchange: Exchange, cert: Path, keylog: Path) -> List[Chunk]:
    chunks: List[Chunk] = []

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(cert), str(cert.with_name("key.pem")))

    server_sock = socket.socket()
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)

    relay_sock = socket.socket()
    relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_sock.bind(("127.0.0.1", 0))
    relay_sock.listen(1)

    server_thread = threading.Thread(
        target=_serve_once, args=(server_sock, server_ctx, exchange.response),
        daemon=True,
    )
    relay_thread = threading.Thread(
        target=_relay_once, args=(relay_sock, server_sock.getsockname(), chunks),
        daemon=True,
    )
    server_thread.start()
    relay_thread.start()

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(str(cert))
    client_ctx.keylog_filename = str(keylog)   # appends across sessions

    raw = socket.create_connection(relay_sock.getsockname())
    with client_ctx.wrap_socket(raw, server_hostname=exchange.host) as tls:
        tls.sendall(exchange.request)
        received = b""
        while len(received) < len(exchange.response):
            try:
                chunk = tls.recv(16384)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            received += chunk

    relay_thread.join(timeout=5)
    server_thread.join(timeout=5)
    server_sock.close()
    relay_sock.close()
    return chunks


# --------------------------------------------------------------------------
# keep-alive fixture
# --------------------------------------------------------------------------
#
# Exists to prove one specific design claim: that `tcp.stream` is a
# CONNECTION id and not a transaction id, so pairing a request to its
# response by stream is wrong. One connection, three transactions, one
# stream. Anything grouping by stream sees six observations in one bucket
# and cannot say which response answered which request.


KEEPALIVE_EXCHANGES: List[Exchange] = [
    Exchange(
        host="api.target-practice.test",
        request=_request("GET", f"/ka/one?i=1", "api.target-practice.test",
                         {"Accept": "application/json"}),
        response=_response("200 OK", {"Content-Type": "application/json"},
                           b'{"n":1}'),
    ),
    Exchange(
        host="api.target-practice.test",
        request=_request("GET", f"/ka/two?i=2", "api.target-practice.test",
                         {"Accept": "application/json"}),
        response=_response("404 Not Found", {"Content-Type": "application/json"},
                           b'{"e":"nope"}'),
    ),
    Exchange(
        host="api.target-practice.test",
        request=_request("POST", f"/ka/three", "api.target-practice.test",
                         {"Content-Type": "application/json"}, body=b'{"x":3}'),
        response=_response("201 Created", {"Content-Type": "application/json"},
                           b'{"n":3}'),
    ),
]


def _serve_keepalive(listener: socket.socket, context: ssl.SSLContext,
                     responses: List[bytes]) -> None:
    """One TLS connection, several request/response rounds."""
    try:
        raw, _ = listener.accept()
        with context.wrap_socket(raw, server_side=True) as tls:
            buffer = b""
            for response in responses:
                while b"\r\n\r\n" not in buffer:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    buffer += chunk
                head, _, buffer = buffer.partition(b"\r\n\r\n")
                # Drain any declared body so the next round starts clean.
                length = 0
                for line in head.decode("latin-1").split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        length = int(line.split(":", 1)[1].strip())
                while len(buffer) < length:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk
                buffer = buffer[length:]
                tls.sendall(response)
    except (ssl.SSLError, OSError):
        pass


def capture_keepalive_session(keylog: Path) -> List[Tuple[Exchange, List[Chunk]]]:
    """Three transactions over ONE TLS connection.

    Returned as a single pseudo-session so `build_frames` renders it as one
    TCP stream — which is the whole point.
    """
    chunks: List[Chunk] = []
    with tempfile.TemporaryDirectory() as d:
        cert, _ = _self_signed(Path(d))

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(cert), str(cert.with_name("key.pem")))

        server_sock = socket.socket()
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)

        relay_sock = socket.socket()
        relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        relay_sock.bind(("127.0.0.1", 0))
        relay_sock.listen(1)

        server_thread = threading.Thread(
            target=_serve_keepalive,
            args=(server_sock, server_ctx,
                  [e.response for e in KEEPALIVE_EXCHANGES]),
            daemon=True,
        )
        relay_thread = threading.Thread(
            target=_relay_once,
            args=(relay_sock, server_sock.getsockname(), chunks),
            daemon=True,
        )
        server_thread.start()
        relay_thread.start()

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.load_verify_locations(str(cert))
        client_ctx.keylog_filename = str(keylog)

        raw = socket.create_connection(relay_sock.getsockname())
        with client_ctx.wrap_socket(
            raw, server_hostname=KEEPALIVE_EXCHANGES[0].host
        ) as tls:
            for exchange in KEEPALIVE_EXCHANGES:
                tls.sendall(exchange.request)
                received = b""
                while len(received) < len(exchange.response):
                    try:
                        chunk = tls.recv(16384)
                    except (ssl.SSLError, OSError):
                        break
                    if not chunk:
                        break
                    received += chunk
                time.sleep(0.01)   # keep the rounds separable on the wire

        relay_thread.join(timeout=5)
        server_thread.join(timeout=5)
        server_sock.close()
        relay_sock.close()

    return [(KEEPALIVE_EXCHANGES[0], chunks)] if chunks else []


def capture_session(keylog: Path) -> List[Tuple[Exchange, List[Chunk]]]:
    """Run every exchange, returning each with the ciphertext it produced."""
    out: List[Tuple[Exchange, List[Chunk]]] = []
    with tempfile.TemporaryDirectory() as d:
        cert, _ = _self_signed(Path(d))
        for exchange in EXCHANGES:
            chunks = _one_exchange(exchange, cert, keylog)
            if chunks:
                out.append((exchange, chunks))
    return out


# --------------------------------------------------------------------------
# pcap writing, with real TCP sequencing
# --------------------------------------------------------------------------


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + payload


def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 6, 0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    ) + payload


def _tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
         payload: bytes = b"") -> bytes:
    return struct.pack(
        ">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0
    ) + payload


def build_frames(
    sessions: List[Tuple[Exchange, List[Chunk]]]
) -> List[Tuple[float, bytes]]:
    """Render each recorded session as its own correctly sequenced TCP stream.

    Sequence numbers must be right or Wireshark will not reassemble the TLS
    records, and without reassembly there is nothing to decrypt — the keylog
    would be blamed for what is actually a malformed capture.

    Each exchange gets a distinct client port so tshark assigns it a distinct
    `tcp.stream`, which is what makes the per-finding display filters point
    at the right conversation.
    """
    frames: List[Tuple[float, bytes]] = []

    for index, (exchange, chunks) in enumerate(sessions):
        if not chunks:
            continue
        server_ip = HOSTS[exchange.host]
        client_port = 54321 + index
        start = chunks[0][0] - 0.002
        c_seq, s_seq = 1000, 5000

        def out(ts: float, from_client: bool, seq: int, ack: int,
                flags: int, payload: bytes = b"",
                _sp=client_port, _ip=server_ip) -> None:
            if from_client:
                pkt = _tcp(_sp, 443, seq, ack, flags, payload)
                frames.append((ts, _eth(_ipv4(CLIENT_IP, _ip, pkt))))
            else:
                pkt = _tcp(443, _sp, seq, ack, flags, payload)
                frames.append((ts, _eth(_ipv4(_ip, CLIENT_IP, pkt))))

        out(start, True, c_seq, 0, 0x02)                     # SYN
        out(start + 0.0005, False, s_seq, c_seq + 1, 0x12)   # SYN-ACK
        c_seq += 1
        s_seq += 1
        out(start + 0.001, True, c_seq, s_seq, 0x10)         # ACK

        for ts, from_client, data in chunks:
            if from_client:
                out(ts, True, c_seq, s_seq, 0x18, data)
                c_seq += len(data)
            else:
                out(ts, False, s_seq, c_seq, 0x18, data)
                s_seq += len(data)

        last = chunks[-1][0]
        out(last + 0.001, True, c_seq, s_seq, 0x11)          # FIN-ACK
        out(last + 0.002, False, s_seq, c_seq + 1, 0x11)

    frames.sort(key=lambda f: f[0])
    return frames


def write_pcap(path: Path, frames: List[Tuple[float, bytes]]) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, data in frames:
            seconds = int(ts)
            handle.write(struct.pack(
                "<IIII", seconds, int((ts - seconds) * 1_000_000),
                len(data), len(data)
            ))
            handle.write(data)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    pcap, keylog = Path(sys.argv[1]), Path(sys.argv[2])
    pcap.parent.mkdir(parents=True, exist_ok=True)
    if keylog.exists():
        keylog.unlink()   # keylog_filename appends; stale keys confuse nothing
                          # but make the line count meaningless

    sessions = capture_session(keylog)
    if not sessions:
        print("no ciphertext recorded — TLS handshake failed", file=sys.stderr)
        return 1

    frames = build_frames(sessions)
    write_pcap(pcap, frames)
    total = sum(len(c[2]) for _, chunks in sessions for c in chunks)
    print(f"{pcap}: {len(frames)} frames, {len(sessions)} sessions, {total} TLS bytes")
    print(f"{keylog}: {len(keylog.read_text().splitlines())} keylog lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
