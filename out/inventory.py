"""Endpoint and parameter inventory.

NOT a findings report. This is reconnaissance output: what the application
actually talked to while you used it. For bug-bounty work it is often the
most useful thing the tool produces, because it comes from traffic the app
genuinely made rather than from guessing at paths — a crawler finds the links
on a page, this finds the API the client calls.

PATH TEMPLATING is what makes it readable. Raw paths produce one row per
object id:

    /v2/users/4417/orders
    /v2/users/4418/orders
    /v2/users/9902/orders

Collapsed to `/v2/users/{id}/orders`, that is one endpoint seen three times —
and the collapse itself is a finding, because a segment that varies across
requests is an object reference, and a NUMERIC one is an enumeration
candidate. The templater therefore reports what each placeholder replaced,
rather than throwing it away.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

from core.model import Series

__all__ = ["build_inventory", "render_inventory", "template_path", "Inventory"]


# --------------------------------------------------------------------------
# path templating
# --------------------------------------------------------------------------


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_NUMERIC = re.compile(r"^\d+$")
_ULID = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_BASE64ISH = re.compile(r"^[A-Za-z0-9_\-]{22,}$")


def template_path(path: str) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
    """Collapse identifier-looking segments. Returns (template, replacements).

    Order matters: UUID and ULID before the generic opaque check, or a UUID
    gets labelled `{opaque}` and the more specific information is lost.

    `{id}` is reported separately from `{uuid}` and `{opaque}` on purpose —
    only the numeric one implies enumerability, and conflating them would
    turn every REST API into an apparent IDOR finding.
    """
    segments = path.split("/")
    out: List[str] = []
    replaced: List[Tuple[str, str]] = []

    for segment in segments:
        if not segment:
            out.append(segment)
            continue
        if _NUMERIC.match(segment):
            out.append("{id}")
            replaced.append(("{id}", segment))
        elif _UUID.match(segment):
            out.append("{uuid}")
            replaced.append(("{uuid}", segment))
        elif _ULID.match(segment):
            out.append("{ulid}")
            replaced.append(("{ulid}", segment))
        elif _HEX.match(segment):
            out.append("{hash}")
            replaced.append(("{hash}", segment))
        elif _BASE64ISH.match(segment) and not segment.isalpha():
            out.append("{opaque}")
            replaced.append(("{opaque}", segment))
        else:
            out.append(segment)

    return "/".join(out), tuple(replaced)


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------


@dataclass
class Endpoint:
    template: str
    methods: Set[str] = field(default_factory=set)
    query_params: Set[str] = field(default_factory=set)
    statuses: Set[str] = field(default_factory=set)
    content_types: Set[str] = field(default_factory=set)
    requests: int = 0
    #: placeholder -> the concrete values seen there
    identifiers: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    authenticated: bool = False
    anonymous: bool = False
    streams: Set[int] = field(default_factory=set)

    @property
    def enumerable(self) -> bool:
        """A numeric identifier with more than one observed value.

        One value proves nothing — every REST path has an id in it. Two or
        more adjacent values are what make enumeration plausible, and that is
        a far quieter signal than flagging `{id}` on sight.
        """
        values = self.identifiers.get("{id}", set())
        return len(values) >= 2

    @property
    def mixed_auth(self) -> bool:
        """Seen both with and without credentials — a privilege-boundary
        candidate worth probing, since the server clearly accepts both."""
        return self.authenticated and self.anonymous


@dataclass
class Host:
    name: str
    scheme: str
    endpoints: Dict[str, Endpoint] = field(default_factory=dict)
    requests: int = 0

    def endpoint(self, template: str) -> Endpoint:
        if template not in self.endpoints:
            self.endpoints[template] = Endpoint(template=template)
        return self.endpoints[template]


@dataclass
class Inventory:
    hosts: Dict[str, Host] = field(default_factory=dict)

    @property
    def endpoint_count(self) -> int:
        return sum(len(h.endpoints) for h in self.hosts.values())

    @property
    def parameter_count(self) -> int:
        return len({
            param
            for host in self.hosts.values()
            for endpoint in host.endpoints.values()
            for param in endpoint.query_params
        })

    def to_json(self) -> Mapping[str, object]:
        return {
            "hosts": [
                {
                    "host": host.name,
                    "scheme": host.scheme,
                    "requests": host.requests,
                    "endpoints": [
                        {
                            "template": e.template,
                            "methods": sorted(e.methods),
                            "query_params": sorted(e.query_params),
                            "statuses": sorted(e.statuses),
                            "content_types": sorted(e.content_types),
                            "requests": e.requests,
                            "identifiers": {
                                k: sorted(v)[:10] for k, v in e.identifiers.items()
                            },
                            "enumerable": e.enumerable,
                            "mixed_auth": e.mixed_auth,
                            "streams": sorted(e.streams),
                        }
                        for e in sorted(host.endpoints.values(), key=lambda x: x.template)
                    ],
                }
                for host in sorted(self.hosts.values(), key=lambda h: h.name)
            ],
            "endpoint_count": self.endpoint_count,
            "parameter_count": self.parameter_count,
        }


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------


def build_inventory(series: Sequence[Series]) -> Inventory:
    """Derive the inventory from the http observations already collected.

    Built from `Series` rather than re-reading the capture, so the inventory
    is free once the analysis has run.
    """
    inventory = Inventory()

    for one in series:
        if one.channel.domain != "http":
            continue
        host_name = one.channel.dims.get("host", "?")
        scheme = one.channel.dims.get("scheme", "https")
        host = inventory.hosts.get(host_name)
        if host is None:
            host = Host(name=host_name, scheme=scheme)
            inventory.hosts[host_name] = host

        for obs in one.observations:
            attrs = obs.attrs
            if obs.kind == "http_request":
                raw_path = str(attrs.get("path", "/"))
                template, replacements = template_path(raw_path)
                endpoint = host.endpoint(template)
                endpoint.requests += 1
                host.requests += 1
                endpoint.methods.add(str(attrs.get("method", "?")))
                endpoint.query_params.update(attrs.get("params", ()) or ())
                for placeholder, value in replacements:
                    endpoint.identifiers[placeholder].add(value)
                if attrs.get("authorization") or attrs.get("cookie"):
                    endpoint.authenticated = True
                else:
                    endpoint.anonymous = True
                if obs.locus and obs.locus.stream is not None:
                    endpoint.streams.add(obs.locus.stream)

            elif obs.kind == "http_response":
                # Responses carry the request path forward from the profile,
                # so a status lands on the endpoint that produced it rather
                # than on whatever the response frame happened to say.
                raw_path = str(attrs.get("request_path") or attrs.get("path", "/"))
                template, _ = template_path(raw_path)
                endpoint = host.endpoint(template)
                endpoint.statuses.add(str(attrs.get("status", "?")))
                ctype = str(attrs.get("content_type", ""))
                if ctype:
                    endpoint.content_types.add(ctype.split(";")[0])

    return inventory


# --------------------------------------------------------------------------
# render
# --------------------------------------------------------------------------


def render_inventory(inventory: Inventory) -> str:
    if not inventory.hosts:
        return ""

    lines: List[str] = [
        "",
        "=" * 72,
        f"INVENTORY   {len(inventory.hosts)} host(s)   "
        f"{inventory.endpoint_count} endpoint(s)   "
        f"{inventory.parameter_count} distinct parameter(s)",
        "=" * 72,
        "",
        "Observed traffic only — this is what the client actually called, not",
        "a guess at what exists. Absence here is not absence on the server.",
    ]

    for host in sorted(inventory.hosts.values(), key=lambda h: h.name):
        lines += ["", f"  {host.scheme}://{host.name}   ({host.requests} request(s))"]
        for endpoint in sorted(host.endpoints.values(), key=lambda e: e.template):
            methods = ",".join(sorted(endpoint.methods)) or "-"
            statuses = ",".join(sorted(endpoint.statuses)) or "-"
            flags = []
            if endpoint.enumerable:
                values = sorted(endpoint.identifiers["{id}"], key=_numeric_key)
                flags.append(f"ENUMERABLE {{id}} seen: {', '.join(values[:4])}")
            if endpoint.mixed_auth:
                flags.append("SEEN BOTH AUTHENTICATED AND ANONYMOUS")

            lines.append(
                f"    {methods:<12} {endpoint.template:<40} "
                f"-> {statuses}  x{endpoint.requests}"
            )
            if endpoint.query_params:
                lines.append(
                    f"      params: {', '.join(sorted(endpoint.query_params))}"
                )
            for flag in flags:
                lines.append(f"      {flag}")
            if endpoint.streams:
                filt = (
                    f"tcp.stream eq {next(iter(sorted(endpoint.streams)))}"
                    if len(endpoint.streams) == 1
                    else "tcp.stream in {" + ",".join(map(str, sorted(endpoint.streams))) + "}"
                )
                lines.append(f"      {filt}")

    return "\n".join(lines)


def _numeric_key(value: str):
    try:
        return (0, int(value))
    except ValueError:
        return (1, value)
