"""Turn parsed HTTP/1.x messages into `http`-domain Observations.

Separated from `capture/http1.py` on purpose: that module knows HTTP and
nothing about this tool's model, this one knows the model and nothing about
byte framing. The seam is `HttpMessage`.

THE ATTRIBUTE NAMES HERE ARE A CONTRACT, not a choice. They match
`capture/tshark.py`'s HttpProfile exactly, which is what lets every inspector
in `inspectors/` and every rule in `ontology/http.py` run against natively
parsed HTTP with no changes at all. `tests/test_http_native.py` asserts the
two sources agree, because the failure mode otherwise is silent: an inspector
reads `attrs.get("set_cookie")`, finds nothing, and reports no problem — which
is indistinguishable from a clean response.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from capture.http1 import HttpMessage, HttpStream
from core.model import Channel, Direction, Entity, Locus, Observation

__all__ = ["HttpTracker"]

#: Body bytes decoded to text for the inspectors. They look for secrets and
#: markers, so a sample is enough and the full body is never retained.
_TEXT_LIMIT = 8192


def _text(body: bytes) -> str:
    if not body:
        return ""
    return body[:_TEXT_LIMIT].decode("utf-8", "replace")


class HttpTracker:
    """Per-connection HTTP state for one capture.

    Holds the request context that a response needs but does not carry. CORS
    reflection can only be judged by comparing a response's Allow-Origin
    against the REQUEST's Origin, and those are two different messages — so
    the request side is remembered here, exactly as the tshark profile does.
    """

    def __init__(self, source_name: str = "") -> None:
        self.source_name = source_name
        self._streams: Dict[int, HttpStream] = {}
        self._origin: Dict[int, str] = {}
        self._request_path: Dict[int, str] = {}
        #: Hosts seen per connection, so a response can be attributed to the
        #: same channel as its request. A response has no Host header.
        self._host: Dict[int, str] = {}
        self.stats = {"requests": 0, "responses": 0}

    def feed(
        self,
        stream: int,
        from_client: bool,
        payload: bytes,
        frame: int,
        ts: float,
        client: str,
        server: str,
        dport: int,
    ) -> List[Observation]:
        state = self._streams.get(stream)
        if state is None:
            state = self._streams[stream] = HttpStream()

        out: List[Observation] = []
        for message in state.feed(from_client, payload, frame):
            observation = self._observe(
                state, stream, message, ts, client, server, dport
            )
            if observation is not None:
                out.append(observation)
        return out

    # ----------------------------------------------------------------------

    def _observe(
        self,
        state: HttpStream,
        stream: int,
        message: HttpMessage,
        ts: float,
        client: str,
        server: str,
        dport: int,
    ) -> Optional[Observation]:
        headers = message.headers
        scheme = "https" if dport == 443 else "http"

        if message.is_request:
            self.stats["requests"] += 1
            host = headers.get("host") or self._host.get(stream) or server
            self._host[stream] = host
            return self._request(
                state, stream, message, ts, client, server, host, scheme
            )

        self.stats["responses"] += 1
        host = self._host.get(stream, server)
        return self._response(
            state, stream, message, ts, client, server, host, scheme
        )

    def _request(
        self, state, stream, message, ts, client, server, host, scheme
    ) -> Observation:
        # A request target is usually origin-form ("/a/b?c=1") but may be
        # absolute-form through a proxy. urlsplit handles both; taking the
        # path off an absolute-form target without it yields the whole URL
        # as the path and the inventory templates nonsense.
        split = urlsplit(message.target)
        path = split.path or "/"
        query = split.query
        params: Tuple[str, ...] = (
            tuple(key for key, _ in parse_qsl(query)) if query else ()
        )
        full_uri = (
            message.target if split.scheme
            else f"{scheme}://{host}{message.target}"
        )

        origin = headers_get(message, "origin")
        if origin:
            self._origin[stream] = origin
        self._request_path[stream] = path

        # FIFO pairing. See the honesty note in capture/http1.py: this is
        # where it would mis-pair under pipelining.
        state.pending.append((message.frame, ts, path))

        attrs: Dict[str, Any] = {
            "encrypted": scheme == "https",
            "decrypted": True,
            "host": host,
            "path": path,
            "headers": dict(message.headers),
            "stream": str(stream),
            "http2_stream": "",
            # The request's own frame is the transaction id, matching the
            # tshark profile's `{stream}:{frame}` convention so that
            # `group_by("txn")` behaves identically across both sources.
            "txn": f"{stream}:{message.frame}",
            "method": message.method,
            "full_uri": full_uri,
            "query": query,
            "params": params,
            "authorization": headers_get(message, "authorization"),
            "cookie": headers_get(message, "cookie"),
            "referer": headers_get(message, "referer"),
            "user_agent": headers_get(message, "user-agent"),
            "body_text": _text(message.body),
        }
        if message.body_truncated or message.body_unknown:
            attrs["body_truncated"] = "1"

        return Observation(
            ts=ts,
            channel=_channel(scheme, host, client, server),
            direction=Direction.EGRESS,
            size=_size(message),
            kind="http_request",
            wire_size=None,
            attrs=attrs,
            locus=Locus(source=self.source_name, frames=(message.frame,)),
        )

    def _response(
        self, state, stream, message, ts, client, server, host, scheme
    ) -> Observation:
        attrs: Dict[str, Any] = {
            "encrypted": scheme == "https",
            "decrypted": True,
            "host": host,
            "path": self._request_path.get(stream, "/"),
            "headers": dict(message.headers),
            "stream": str(stream),
            "http2_stream": "",
            "status": message.status,
            "content_type": headers_get(message, "content-type"),
            # A response setting three cookies collapses to one in a flat
            # dict, and the cookie inspector would then judge two of them as
            # though they did not exist. `repeated` preserves them.
            "set_cookie": list(
                message.repeated.get("set-cookie")
                or ([headers_get(message, "set-cookie")]
                    if headers_get(message, "set-cookie") else [])
            ),
            "location": headers_get(message, "location"),
            "request_origin": self._origin.get(stream, ""),
            "request_path": self._request_path.get(stream, "/"),
            "body_text": _text(message.body),
        }
        if message.body_truncated or message.body_unknown:
            attrs["body_truncated"] = "1"

        if state.pending:
            request_frame, request_ts, request_path = state.pending.pop(0)
            attrs["txn"] = f"{stream}:{request_frame}"
            attrs["request_frame"] = str(request_frame)
            attrs["request_path"] = request_path
            attrs["path"] = request_path
            elapsed = ts - request_ts
            # Left unset rather than zeroed when it cannot be computed, so a
            # consumer can tell "fast" from "unknown" — the latency oracle
            # depends on that distinction.
            if elapsed >= 0:
                attrs["elapsed_s"] = elapsed

        # The FIRST response on a connection carries TCP slow start, pool
        # initialisation and whatever the server does cold: systematically
        # slower for reasons unrelated to the application. Two of them in a
        # sample of ten fabricate a latency cluster, which is a false
        # positive this project has already shipped once.
        attrs["connection_warm_up"] = not state.answered
        state.answered = True

        return Observation(
            ts=ts,
            channel=_channel(scheme, host, client, server),
            direction=Direction.INGRESS,
            size=_size(message),
            kind="http_response",
            wire_size=None,
            attrs=attrs,
            locus=Locus(source=self.source_name, frames=(message.frame,)),
        )


def headers_get(message: HttpMessage, key: str) -> str:
    return message.headers.get(key, "")


def _channel(scheme: str, host: str, client: str, server: str) -> Channel:
    # dims are {scheme, host}: the channel is a HOST, not an endpoint, with
    # method/path/status in attrs. See the HttpProfile docstring and
    # docs/ADR-001 for why endpoint-level dims were rejected.
    return Channel(
        domain="http",
        dims={"scheme": scheme, "host": str(host)},
        initiator=Entity("ip", client),
        responder=Entity("ip", server),
    )


def _size(message: HttpMessage) -> int:
    """Application message size: headers plus body.

    Body alone would make a header-heavy request look empty to `Asymmetry`,
    which is the primitive most sensitive to this — a request carrying a 4 kB
    cookie jar and no body is not a zero-byte message.
    """
    header_bytes = sum(
        len(key) + len(value) + 4 for key, value in message.headers.items()
    )
    return header_bytes + len(message.body)
