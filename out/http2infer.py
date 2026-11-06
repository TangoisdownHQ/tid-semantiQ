"""How many requests did an HTTP/2 connection carry — estimated, without keys.

HTTP/2 multiplexes many requests over one TLS connection, so a single
encrypted channel to a web server can be one page fetch or a thousand-request
scan, and the volume totals do not tell them apart. The content is sealed,
but the TLS record FRAMING is not: each record's cleartext header gives its
direction and length. On an HTTP/2 connection a client request is a HEADERS
frame that rides a small outbound application-data record, so the count of
those records is a proxy for the number of requests — enough to answer "did
this phase make ten requests or ten thousand?" without decrypting anything.

IT IS AN ESTIMATE, AND SAYS SO. The proxy errs in both directions and the
caller must carry the caveat, never a bare number:

  INFLATED by HTTP/2 control frames — SETTINGS, WINDOW_UPDATE, PING, the
  connection preface — which are also small outbound records but are not
  requests.
  DEFLATED by TLS coalescing, where one record carries several HTTP/2 frames
  (so several requests), and by request bodies that span records.

So this is offered only for h2 connections (where the multiplexing makes the
question meaningful), as a magnitude, with the basis shown. http/1.1 is a
different shape — closer to one exchange per request — and is left to the
ordinary exchange and record reporting.
"""

from __future__ import annotations

from typing import Optional, Sequence


def estimate_requests(alpn: Sequence[str],
                      out_records: int,
                      in_records: int = 0) -> Optional[dict]:
    """A request-count estimate for an HTTP/2 connection, or None.

    Returns None unless ALPN negotiated h2 — the only case where "how many
    requests" is both ambiguous (multiplexed) and answerable (one record
    each, roughly). `out_records` / `in_records` are the outbound / inbound
    application-data record counts the TLS record walker already measured.
    """
    if "h2" not in [a.strip() for a in alpn]:
        return None
    if out_records <= 0:
        return None
    return {
        "requests_proxy": out_records,
        "responses_proxy": in_records,
        "basis": (f"{out_records:,} outbound application-data record(s)"),
        "caveat": (
            "a proxy, not a count: HTTP/2 control frames (SETTINGS, "
            "WINDOW_UPDATE, PING) inflate it and TLS record coalescing "
            "deflates it"
        ),
    }
