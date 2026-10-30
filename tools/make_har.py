#!/usr/bin/env python3
"""Emit a HAR from the same exchange list the TLS pcap fixture uses.

One source of truth, two capture paths. The pcap fixture puts those exchanges
through real TLS and a recording relay; this writes them as a HAR the way a
browser would. Running both through the analyzers and comparing findings is
the real test of whether the capture/analysis boundary holds — if HAR and
pcap disagree, a capture plugin is leaking its format into the findings.

    python3 tools/make_har.py out/session.har
    python3 tools/make_har.py out/tokens.har --tokens
    python3 tools/make_har.py out/latency.har --latency
    python3 tools/make_har.py out/fixation.har --fixation
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from tools.make_tls_pcap import EXCHANGES, HOSTS

BASE_TIME = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)


def _split_message(raw: bytes) -> Tuple[str, List[Tuple[str, str]], str]:
    """(start line, headers, body) from raw HTTP bytes."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    start = lines[0] if lines else ""
    headers: List[Tuple[str, str]] = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers.append((name.strip(), value.strip()))
    return start, headers, body.decode("utf-8", "replace")


def _cookies_from(headers: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """Structured Set-Cookie entries, as an exporter would write them.

    Deliberately LOSSY — Domain and SameSite are dropped here, exactly as
    several real exporters do. The raw `Set-Cookie` header is also emitted,
    and `HarSource` prefers it, so this exercises that preference rather than
    quietly handing the parser a perfect structured form it will never see in
    the wild.
    """
    out = []
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        pair = value.split(";")[0]
        cookie_name, _, cookie_value = pair.partition("=")
        out.append({
            "name": cookie_name.strip(),
            "value": cookie_value.strip(),
            "path": "/",
            "httpOnly": "httponly" in value.lower(),
            "secure": "secure" in value.lower(),
        })
    return out


def build_har() -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []

    for index, exchange in enumerate(EXCHANGES):
        req_line, req_headers, req_body = _split_message(exchange.request)
        res_line, res_headers, res_body = _split_message(exchange.response)

        method, _, target = req_line.partition(" ")
        target = target.rsplit(" ", 1)[0]
        url = f"https://{exchange.host}{target}"

        status_parts = res_line.split(" ", 2)
        status = int(status_parts[1]) if len(status_parts) > 1 else 0
        status_text = status_parts[2] if len(status_parts) > 2 else ""

        query = []
        if "?" in target:
            from urllib.parse import parse_qsl
            query = [
                {"name": k, "value": v}
                for k, v in parse_qsl(target.split("?", 1)[1], keep_blank_values=True)
            ]

        started = BASE_TIME + timedelta(seconds=index * 2)
        content_type = next(
            (v for k, v in res_headers if k.lower() == "content-type"), ""
        )

        entry: Dict[str, Any] = {
            "startedDateTime": started.isoformat().replace("+00:00", "Z"),
            "time": 42.5 + index,
            "serverIPAddress": HOSTS[exchange.host],
            "request": {
                "method": method,
                "url": url,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": n, "value": v} for n, v in req_headers],
                "queryString": query,
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(req_body),
            },
            "response": {
                "status": status,
                "statusText": status_text,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": n, "value": v} for n, v in res_headers],
                "cookies": _cookies_from(res_headers),
                "content": {
                    "size": len(res_body),
                    "mimeType": content_type,
                    "text": res_body,
                },
                "redirectURL": next(
                    (v for k, v in res_headers if k.lower() == "location"), ""
                ),
                "headersSize": -1,
                "bodySize": len(res_body),
            },
            "cache": {},
            "timings": {"send": 1.0, "wait": 40.0, "receive": 1.5},
        }
        if req_body:
            entry["request"]["postData"] = {
                "mimeType": next(
                    (v for k, v in req_headers if k.lower() == "content-type"),
                    "application/octet-stream",
                ),
                "text": req_body,
            }
        entries.append(entry)

    # A failed request with no response — exporters emit these, and emitting
    # a phantom status-0 response for one would invent an endpoint.
    entries.append({
        "startedDateTime": (BASE_TIME + timedelta(seconds=99)).isoformat().replace("+00:00", "Z"),
        "time": 0,
        "request": {
            "method": "GET",
            "url": "https://api.target-practice.test/v2/never-answered",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Host", "value": "api.target-practice.test"}],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0,
        },
        "response": {
            "status": 0, "statusText": "", "httpVersion": "",
            "headers": [], "cookies": [],
            "content": {"size": 0, "mimeType": ""},
            "redirectURL": "", "headersSize": -1, "bodySize": -1,
        },
        "cache": {}, "timings": {},
    })

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "tid-semantiQ fixture", "version": "0.1"},
            "pages": [],
            "entries": entries,
        }
    }


# --------------------------------------------------------------------------
# token-quality fixture
# --------------------------------------------------------------------------
#
# Kept separate from build_har() on purpose. The agreement test compares the
# HAR and pcap paths over one shared exchange list, and adding twelve logins
# to that list would mean regenerating the pcap fixture for an analysis that
# has nothing to do with packet timing.


def build_token_har(samples: int = 12) -> Dict[str, Any]:
    """Logins minting deliberately weak session tokens, on three hosts.

    Each host exercises a different provable weakness, so the analyser's
    three independent signals can be tested apart from one another:

        counter.*   sequential hex — clustered keyspace
        struct.*    base64 of "<user>:<email>:<n>" — decodable, forgeable
        framed.*    a long fixed prefix with four varying hex characters
    """
    entries: List[Dict[str, Any]] = []

    def login(host: str, index: int, cookie: str, body: str = "{}") -> None:
        started = BASE_TIME + timedelta(seconds=index * 3)
        entries.append({
            "startedDateTime": started.isoformat().replace("+00:00", "Z"),
            "time": 30.0,
            "serverIPAddress": "203.0.113.90",
            "request": {
                "method": "POST",
                "url": f"https://{host}/login",
                "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": "Host", "value": host},
                    {"name": "Content-Type", "value": "application/json"},
                ],
                "queryString": [], "cookies": [],
                "headersSize": -1, "bodySize": len(body),
                "postData": {
                    "mimeType": "application/json",
                    "text": body,
                },
            },
            "response": {
                "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": "Content-Type", "value": "application/json"},
                    {"name": "Set-Cookie", "value": cookie},
                ],
                "cookies": [],
                "content": {"size": 2, "mimeType": "application/json", "text": "{}"},
                "redirectURL": "", "headersSize": -1, "bodySize": 2,
            },
            "cache": {}, "timings": {"send": 1.0, "wait": 28.0, "receive": 1.0},
        })

    import base64 as _b64

    for index in range(samples):
        # 1 — sequential counter in a nominally 64-bit hex space
        counter = 0x5f3a2b1c00000000 + index
        login(
            "counter.target-practice.test", index,
            f"sessionid={counter:016x}; Path=/; Secure; HttpOnly; SameSite=Lax",
            body='{"email": "victim@target-practice.test"}',
        )

        # 2 — base64 of readable structure including the user's email
        payload = f"user-4417:victim@target-practice.test:{index}".encode()
        token = _b64.urlsafe_b64encode(payload).decode().rstrip("=")
        login(
            "struct.target-practice.test", index,
            f"auth_token={token}; Path=/; Secure; HttpOnly; SameSite=Strict",
            body='{"email": "victim@target-practice.test"}',
        )

        # 3 — 28 fixed characters of framing, 4 varying hex
        login(
            "framed.target-practice.test", index,
            f"JSESSIONID=APP01PROD0000000000000000000{index:04x}"
            "; Path=/; Secure; HttpOnly; SameSite=Lax",
        )

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "tid-semantiQ token fixture", "version": "0.1"},
            "pages": [],
            "entries": entries,
        }
    }


# --------------------------------------------------------------------------
# latency fixtures
# --------------------------------------------------------------------------


def _login_entry(index: int, host: str, wait_ms: float, status: int,
                 body: str, *, new_connection: bool) -> Dict[str, Any]:
    """One login transaction with explicitly controlled server wait time.

    HAR is the right fixture format for latency work: `timings.wait` is
    server think-time to the millisecond, and `connect`/`ssl` say whether
    this entry paid connection setup. Reproducing that over real sockets
    would mean real sleeps and a slow, flaky test.
    """
    started = BASE_TIME + timedelta(seconds=index * 2)
    setup = {"connect": 12.0, "ssl": 24.0} if new_connection else {"connect": -1, "ssl": -1}
    return {
        "startedDateTime": started.isoformat().replace("+00:00", "Z"),
        "time": wait_ms + 2.0 + (36.0 if new_connection else 0.0),
        "request": {
            "method": "POST", "url": f"https://{host}/login",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Host", "value": host},
                        {"name": "Content-Type", "value": "application/json"}],
            "queryString": [], "cookies": [],
            "headersSize": -1, "bodySize": 0,
            "postData": {"mimeType": "application/json", "text": "{}"},
        },
        "response": {
            "status": status, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "cookies": [],
            "content": {"size": len(body), "mimeType": "application/json",
                        "text": body},
            "redirectURL": "", "headersSize": -1, "bodySize": len(body),
        },
        "cache": {},
        "timings": {"send": 1.0, "wait": wait_ms, "receive": 1.0, **setup},
    }


def build_latency_har(
    *,
    oracle: bool = True,
    aligned: bool = False,
    jitter_ms: float = 4.0,
    samples: int = 14,
    warm_up_spike_ms: float = 400.0,
    connections: int = 3,
) -> Dict[str, Any]:
    """A login endpoint, with or without a genuine timing oracle.

        oracle=True   half the responses take ~95ms, half ~15ms, identical
                      status and body — the hidden username oracle
        oracle=False  one population with the same jitter and NO real
                      difference, which must produce nothing
        aligned=True  the slow cluster also returns a different status, so
                      the difference is visible without timing analysis

    Every variant plants `connections` first-on-connection responses at
    `warm_up_spike_ms`. Three is realistic — a browser opens several
    connections to a host and each one's first request pays setup. One spike
    alone cannot form a cluster (MIN_PER_CLUSTER is 3), so a single outlier
    would not demonstrate anything; three do, which is exactly why the
    exclusion is needed rather than merely tidy.
    """
    import random

    rng = random.Random(20261023)
    host = "login.target-practice.test"
    entries: List[Dict[str, Any]] = []
    body_same = '{"error": "Invalid credentials"}'

    # First transaction on each connection: slow for reasons unrelated to
    # the application.
    for c in range(connections):
        entries.append(_login_entry(
            c, host, warm_up_spike_ms + rng.uniform(-20, 20), 401, body_same,
            new_connection=True,
        ))

    for index in range(connections, connections + samples):
        if oracle and index % 2 == 0:
            wait = 95.0 + rng.uniform(-jitter_ms, jitter_ms)
            status = 200 if aligned else 401
            body = '{"ok": true}' if aligned else body_same
        else:
            wait = 15.0 + rng.uniform(-jitter_ms, jitter_ms)
            status = 401
            body = body_same
        entries.append(_login_entry(
            index, host, wait, status, body, new_connection=False,
        ))

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "tid-semantiQ latency fixture", "version": "0.1"},
            "pages": [],
            "entries": entries,
        }
    }


# --------------------------------------------------------------------------
# session fixation fixtures
# --------------------------------------------------------------------------


def _entry(index: int, host: str, method: str, target: str, status: int,
           *, cookie: str = "", set_cookie: Sequence[str] = (),
           body: str = "") -> Dict[str, Any]:
    started = BASE_TIME + timedelta(seconds=index * 2)
    req_headers = [{"name": "Host", "value": host}]
    if cookie:
        req_headers.append({"name": "Cookie", "value": cookie})
    if body:
        req_headers.append({"name": "Content-Type", "value": "application/json"})

    res_headers = [{"name": "Content-Type", "value": "application/json"}]
    res_headers += [{"name": "Set-Cookie", "value": c} for c in set_cookie]

    entry: Dict[str, Any] = {
        "startedDateTime": started.isoformat().replace("+00:00", "Z"),
        "time": 20.0,
        "request": {
            "method": method, "url": f"https://{host}{target}",
            "httpVersion": "HTTP/1.1", "headers": req_headers,
            "queryString": [], "cookies": [],
            "headersSize": -1, "bodySize": len(body),
        },
        "response": {
            "status": status, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": res_headers, "cookies": [],
            "content": {"size": 2, "mimeType": "application/json", "text": "{}"},
            "redirectURL": "", "headersSize": -1, "bodySize": 2,
        },
        "cache": {},
        "timings": {"send": 1.0, "wait": 18.0, "receive": 1.0,
                    "connect": -1, "ssl": -1},
    }
    if body:
        entry["request"]["postData"] = {
            "mimeType": "application/json", "text": body,
        }
    return entry


def build_fixation_har(
    *,
    rotates: bool = False,
    login_succeeds: bool = True,
    reissue_same: bool = False,
    requests_after: int = 3,
    session_in_url: bool = False,
) -> Dict[str, Any]:
    """A browse -> login -> browse sequence, with the session either rotated
    or not.

        rotates=False        the identifier survives login — FIXATION
        rotates=True         a new identifier is issued — correct
        login_succeeds=False a 401; nothing is expected to rotate, so this
                             must NOT be reported
        reissue_same=True    the server DOES Set-Cookie after login, to the
                             same value — a non-rotating generator rather
                             than a missing Set-Cookie
        requests_after=0     the capture ends at the login, so rotation
                             cannot be observed — must decline, not accuse
        session_in_url=True  the identifier also travels in a query string
    """
    host = "app.target-practice.test"
    pre, post = "AAAAAAAAAAAAAAAA1111", "BBBBBBBBBBBBBBBB2222"
    entries: List[Dict[str, Any]] = []
    index = 0

    # The anonymous session, already established.
    entries.append(_entry(index, host, "GET", "/", 200,
                          set_cookie=(f"sessionid={pre}; Path=/; HttpOnly",)))
    index += 1
    for _ in range(2):
        target = f"/catalog?sessionid={pre}" if session_in_url else "/catalog"
        entries.append(_entry(index, host, "GET", target, 200,
                              cookie=f"sessionid={pre}"))
        index += 1

    # The authentication attempt.
    after_value = post if rotates else pre
    login_sets: List[str] = []
    if login_succeeds and (rotates or reissue_same):
        login_sets.append(f"sessionid={after_value}; Path=/; HttpOnly")
    entries.append(_entry(
        index, host, "POST", "/login", 200 if login_succeeds else 401,
        cookie=f"sessionid={pre}",
        set_cookie=tuple(login_sets),
        body='{"username": "victim", "password": "hunter2"}',
    ))
    index += 1

    # Authenticated browsing, presenting whatever the client now holds.
    for _ in range(requests_after):
        entries.append(_entry(index, host, "GET", "/account", 200,
                              cookie=f"sessionid={after_value}"))
        index += 1

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "tid-semantiQ fixation fixture", "version": "0.1"},
            "pages": [],
            "entries": entries,
        }
    }


# --------------------------------------------------------------------------
# refresh-token fixtures
# --------------------------------------------------------------------------


def build_refresh_har(
    *,
    rotates: bool = False,
    replay_same_token: bool = False,
    refreshes: int = 4,
    expires_in: int = 900,
    rejected: bool = False,
) -> Dict[str, Any]:
    """A client refreshing its access token several times.

        rotates=True            each response returns a NEW refresh token —
                                correct behaviour, must be silent
        rotates=False           responses return the SAME token
        replay_same_token=True  the same token is PRESENTED twice and
                                accepted both times — observed proof it was
                                never invalidated
        rejected=True           the server returns 400; a rejected refresh
                                says nothing about rotation and must not be
                                judged
    """
    host = "auth.target-practice.test"
    entries: List[Dict[str, Any]] = []
    token = "rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0"

    for index in range(refreshes):
        presented = token
        if rotates and not replay_same_token:
            returned = f"rt_BBBBBBBBBBBBBBBBBBBBBBBBBBBB{index:03d}"
        else:
            returned = token

        body = (
            "grant_type=refresh_token"
            f"&refresh_token={presented}"
            "&client_id=mobile-app"
        )
        if rejected:
            status, payload = 400, '{"error": "invalid_grant"}'
        else:
            status = 200
            fields = {
                "access_token": f"at_{index:04d}" + "C" * 28,
                "token_type": "Bearer",
                "expires_in": expires_in,
            }
            # `rotates` with no replay means a fresh token each time; the
            # no-rotation case omits it entirely half the time, which is the
            # other way servers get this wrong.
            if rotates or index % 2 == 0:
                fields["refresh_token"] = returned
            payload = json.dumps(fields)

        started = BASE_TIME + timedelta(seconds=index * 300)
        entries.append({
            "startedDateTime": started.isoformat().replace("+00:00", "Z"),
            "time": 40.0,
            "request": {
                "method": "POST", "url": f"https://{host}/oauth/token",
                "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": "Host", "value": host},
                    {"name": "Content-Type",
                     "value": "application/x-www-form-urlencoded"},
                ],
                "queryString": [], "cookies": [],
                "headersSize": -1, "bodySize": len(body),
                "postData": {
                    "mimeType": "application/x-www-form-urlencoded",
                    "text": body,
                },
            },
            "response": {
                "status": status, "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Content-Type",
                             "value": "application/json"}],
                "cookies": [],
                "content": {"size": len(payload),
                            "mimeType": "application/json", "text": payload},
                "redirectURL": "", "headersSize": -1, "bodySize": len(payload),
            },
            "cache": {},
            "timings": {"send": 1.0, "wait": 38.0, "receive": 1.0,
                        "connect": -1, "ssl": -1},
        })

        if rotates and not replay_same_token:
            token = returned

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "tid-semantiQ refresh fixture",
                        "version": "0.1"},
            "pages": [],
            "entries": entries,
        }
    }


def main() -> int:
    if not (2 <= len(sys.argv) <= 3):
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    if "--tokens" in sys.argv:
        har = build_token_har()
    elif "--latency" in sys.argv:
        har = build_latency_har()
    elif "--fixation" in sys.argv:
        har = build_fixation_har()
    elif "--refresh" in sys.argv:
        har = build_refresh_har()
    else:
        har = build_har()
    out.write_text(json.dumps(har, indent=1))
    print(f"{out}: {len(har['log']['entries'])} entries")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    raise SystemExit(main())
