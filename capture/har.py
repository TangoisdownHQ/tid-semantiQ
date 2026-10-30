"""HarSource — read a HAR file.

THE POINT OF THIS IS ADOPTION, not capability. Burp, Caido, mitmproxy, and
every browser's devtools export HAR. Supporting it means tid-SemantiQ runs on
traffic someone already has, with no capture, no keylog, and no tshark — so
it composes with the tooling people actually use instead of asking them to
switch.

It also removes the hardest prerequisite. The pcap path needs a capture and
TLS keys; the HAR path needs a file you can produce from a browser in two
clicks. For a first look at a target, that is the difference between
"interesting, I'll try it later" and trying it.

Everything above this file is unchanged. A HAR entry produces the same
`Observation` shape as `HttpProfile`, with the same `attrs` keys, so every
inspector and correlator works on HAR with no modification — which is the
real test of whether the capture/analysis boundary was drawn correctly.

WHAT IS LOST. A HAR has no packets, so there is no `tcp.stream`, no burst
timing, and no behavioural analysis worth the name — the native reader's
cadence work has nothing to chew on. HAR is for content findings only, and
loci report "entry 4" rather than a Wireshark filter that would not work.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from capture.base import CaptureSource
from core.model import Channel, Direction, Entity, Locus, Observation

__all__ = ["HarSource"]


class HarSource(CaptureSource):
    """Read HAR entries as http Observations.

    `retain_bodies` defaults to True: a HAR already contains the bodies on
    disk, so refusing to read them protects nothing. Redaction on output is
    what keeps findings safe, as everywhere else.
    """

    domain = "http"

    def __init__(self, path: Path | str, retain_bodies: bool = True):
        self.path = Path(path)
        self.retain_bodies = retain_bodies
        self.stats = {
            "entries": 0, "observations": 0, "skipped": 0, "undecodable": 0,
        }

    def observations(self) -> Iterator[Observation]:
        try:
            document = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"{self.path.name} is not readable HAR: {exc}") from exc

        entries = (document.get("log") or {}).get("entries")
        if entries is None:
            raise ValueError(
                f"{self.path.name} has no log.entries — not a HAR file"
            )

        for index, entry in enumerate(entries, start=1):
            self.stats["entries"] += 1
            produced = self._entry(entry, index)
            if not produced:
                self.stats["skipped"] += 1
                continue
            self.stats["observations"] += len(produced)
            yield from produced

    # -- per entry ---------------------------------------------------------

    def _entry(self, entry: Mapping[str, Any], index: int) -> List[Observation]:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = request.get("url")
        if not url:
            return []

        split = urlsplit(url)
        host = split.hostname or "?"
        scheme = split.scheme or "https"
        started = _timestamp(entry.get("startedDateTime"))
        if started is None:
            self.stats["undecodable"] += 1
            started = 0.0

        # HAR carries no addresses for either end in most exporters. The
        # server IP is sometimes present as `serverIPAddress`; the client
        # never is. Entities fall back to the hostname so channel identity
        # stays stable, and `Entity.kind` says which it is rather than
        # pretending a hostname is an IP.
        server_ip = entry.get("serverIPAddress") or ""
        responder = (
            Entity("ip", server_ip) if _looks_like_ip(server_ip)
            else Entity("host", host)
        )
        channel = Channel(
            domain="http",
            dims={"scheme": scheme, "host": host},
            initiator=Entity("client", "local"),
            responder=responder,
        )

        req_headers = _headers(request.get("headers"))
        res_headers = _headers(response.get("headers"))
        path = split.path or "/"
        params = tuple(k for k, _ in parse_qsl(split.query)) if split.query else ()

        locus = Locus(
            source=self.path.name,
            frames=(index,),
            kind="har",
            label=f"entry {index}",
        )

        out: List[Observation] = []

        req_body = ((request.get("postData") or {}).get("text") or "")
        out.append(Observation(
            ts=started,
            channel=channel,
            direction=Direction.EGRESS,
            size=_size(req_headers, req_body),
            kind="http_request",
            attrs={
                "encrypted": scheme == "https",
                "decrypted": True,
                "host": host,
                "path": path,
                "headers": req_headers,
                "method": request.get("method", "?"),
                "full_uri": url,
                "query": split.query or "",
                "params": params,
                "authorization": req_headers.get("authorization", ""),
                "cookie": req_headers.get("cookie", "")
                          or _cookie_header(request.get("cookies")),
                "referer": req_headers.get("referer", ""),
                "user_agent": req_headers.get("user-agent", ""),
                # Request bodies matter as much as response bodies: a login
                # POST carries the identity that a weak session token is
                # later found to encode.
                "body_text": req_body,
                # One HAR entry is one transaction, so the entry index is a
                # valid transaction id. `stream` is kept for symmetry with
                # the pcap path but means the same thing here.
                "txn": str(index),
                "stream": str(index),
            },
            payload=req_body.encode("utf-8", "replace") if (req_body and self.retain_bodies) else None,
            locus=locus,
        ))

        status = response.get("status")
        if status in (None, 0):
            # A failed or aborted request has no response. Emitting a
            # zero-status observation would create a phantom endpoint in the
            # inventory and a response for inspectors to read that never
            # existed.
            return out

        content = response.get("content") or {}
        body = content.get("text") or ""
        if content.get("encoding") == "base64":
            body = _from_base64(body)

        # HAR splits Set-Cookie into a structured `cookies` array AND leaves
        # it in headers; exporters vary in which they populate. Prefer the
        # raw header, since cookie ATTRIBUTES (Domain, SameSite, flags) are
        # the finding and some exporters drop them from the structured form.
        set_cookie = _set_cookies(response, res_headers)

        # The response's timestamp is the request plus its elapsed time, so
        # timing is at least internally consistent even though it is not wire
        # timing.
        elapsed_ms = entry.get("time")
        offset = (float(elapsed_ms) / 1000.0) if isinstance(elapsed_ms, (int, float)) and elapsed_ms > 0 else 0.0

        response_attrs_extra: Dict[str, Any] = {}
        timings = entry.get("timings") or {}

        # `timings.wait` is time spent waiting for the server to answer,
        # excluding dns, connect, ssl, send and receive. That is the closest
        # HAR has to server think-time and the right input for a latency
        # comparison — total `time` folds in connection setup, which is
        # exactly the warm-up noise being excluded below.
        wait = timings.get("wait")
        if isinstance(wait, (int, float)) and wait >= 0:
            response_attrs_extra["elapsed_s"] = float(wait) / 1000.0
        elif isinstance(elapsed_ms, (int, float)) and elapsed_ms > 0:
            response_attrs_extra["elapsed_s"] = float(elapsed_ms) / 1000.0

        # HAR sets connect/ssl to -1 on a reused connection, so a positive
        # value means this entry paid setup cost.
        paid_setup = any(
            isinstance(timings.get(phase), (int, float)) and timings[phase] > 0
            for phase in ("connect", "ssl")
        )
        response_attrs_extra["connection_warm_up"] = paid_setup

        out.append(Observation(
            ts=started + offset,
            channel=channel,
            direction=Direction.INGRESS,
            size=_size(res_headers, body),
            kind="http_response",
            attrs={
                "encrypted": scheme == "https",
                "decrypted": True,
                "host": host,
                "path": path,
                "request_path": path,
                "request_origin": req_headers.get("origin", ""),
                "headers": res_headers,
                "status": str(status),
                "content_type": content.get("mimeType", "")
                                or res_headers.get("content-type", ""),
                "set_cookie": set_cookie,
                "location": res_headers.get("location", ""),
                "body_text": body,
                "txn": str(index),
                "stream": str(index),
                **response_attrs_extra,
            },
            payload=body.encode("utf-8", "replace") if (body and self.retain_bodies) else None,
            locus=locus,
        ))
        return out


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _headers(raw: Optional[Sequence[Mapping[str, Any]]]) -> Dict[str, str]:
    """HAR headers are a list of {name, value}. Lowercased for lookup, and
    repeats joined rather than overwritten — losing a second `Set-Cookie`
    would silently drop a finding."""
    headers: Dict[str, str] = {}
    for item in raw or ():
        name = str(item.get("name", "")).strip().lower()
        value = str(item.get("value", "")).strip()
        if not name:
            continue
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return headers


def _set_cookies(
    response: Mapping[str, Any], headers: Mapping[str, str]
) -> Tuple[str, ...]:
    """Set-Cookie values, preferring the raw header form.

    The structured `cookies` array is normalised by the exporter and commonly
    loses attributes — and the attributes (Domain, SameSite, Secure,
    HttpOnly) are precisely what `CookieSecurity` reports on. Reconstructing
    them from the structured form is the fallback, not the primary path.
    """
    raw = headers.get("set-cookie", "")
    if raw:
        # Joined on ", " by _headers; cookie values can contain commas in
        # Expires, so split only where a new `name=` plainly begins.
        parts: List[str] = []
        current = ""
        for chunk in raw.split(", "):
            if "=" in chunk.split(";")[0] and current and not _is_attribute(chunk):
                parts.append(current)
                current = chunk
            else:
                current = f"{current}, {chunk}" if current else chunk
        if current:
            parts.append(current)
        return tuple(parts)

    rebuilt: List[str] = []
    for cookie in response.get("cookies") or ():
        name, value = cookie.get("name"), cookie.get("value", "")
        if not name:
            continue
        bits = [f"{name}={value}"]
        if cookie.get("path"):
            bits.append(f"Path={cookie['path']}")
        if cookie.get("domain"):
            bits.append(f"Domain={cookie['domain']}")
        if cookie.get("expires"):
            bits.append(f"Expires={cookie['expires']}")
        if cookie.get("httpOnly"):
            bits.append("HttpOnly")
        if cookie.get("secure"):
            bits.append("Secure")
        if cookie.get("sameSite"):
            bits.append(f"SameSite={cookie['sameSite']}")
        rebuilt.append("; ".join(bits))
    return tuple(rebuilt)


_COOKIE_ATTRIBUTES = (
    "expires", "max-age", "domain", "path", "secure", "httponly",
    "samesite", "partitioned", "priority",
)


def _is_attribute(chunk: str) -> bool:
    return chunk.strip().split("=")[0].strip().lower() in _COOKIE_ATTRIBUTES


def _cookie_header(cookies: Optional[Sequence[Mapping[str, Any]]]) -> str:
    return "; ".join(
        f"{c.get('name')}={c.get('value', '')}"
        for c in cookies or () if c.get("name")
    )


def _size(headers: Mapping[str, str], body: str) -> int:
    header_bytes = sum(len(k) + len(v) + 4 for k, v in headers.items())
    return header_bytes + len(body.encode("utf-8", "replace"))


def _timestamp(value: Optional[str]) -> Optional[float]:
    """ISO-8601 to epoch seconds.

    `fromisoformat` on Python 3.10 rejects a trailing `Z`, which is what
    every browser actually writes, so it is normalised first. A naive
    datetime is treated as local time — that is what the exporter meant, and
    guessing UTC would shift every timestamp by the operator's offset.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _from_base64(text: str) -> str:
    import base64
    try:
        return base64.b64decode(text).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return ""
