"""Encrypted DNS (DoH / DoT) — naming the blind spot it creates.

The tool earns much of its value from DNS: it names endpoints from the
answers, measures resolution failure, and catches DNS tunnels. Encrypted DNS
removes all of that from view. DNS over HTTPS (DoH) carries the lookup inside
an ordinary HTTPS request to a resolver — `https://cloudflare-dns.com/dns-
query` — so it looks exactly like web traffic on TCP 443; DNS over TLS (DoT)
does the same on its own port, 853. Either way the names a host resolves
become invisible.

A report that then said "no DNS seen" would be wrong in the way that matters
— the resolution happened, it just cannot be read here. So this recognises
the pattern instead and says so: a connection to a KNOWN encrypted-DNS
resolver, by the SNI it requested or by a well-known resolver address on 443
or 853. That turns a silent blind spot into a stated one — and it is a real
security signal too, because malware increasingly moves its command-and-
control lookups to DoH precisely to defeat this kind of monitoring.

Recognition is by a bundled list of the major public providers, matched on
the SNI (strong) or on the resolver IP paired with the DoH/DoT port. It is
not exhaustive — a private DoH endpoint is not on any list — and claims only
"a known resolver", never "all encrypted DNS".
"""

from __future__ import annotations

from typing import Optional, Tuple

__all__ = ["classify_encrypted_dns", "DOH_HOST_SUFFIXES", "RESOLVER_IPS"]

#: SNI suffix -> provider. Suffix match so mozilla.cloudflare-dns.com,
#: chrome.cloudflare-dns.com etc. all resolve to Cloudflare.
DOH_HOST_SUFFIXES = {
    "cloudflare-dns.com": "Cloudflare",
    "one.one.one.one": "Cloudflare",
    "dns.google": "Google",
    "dns.google.com": "Google",
    "quad9.net": "Quad9",
    "opendns.com": "OpenDNS",
    "adguard.com": "AdGuard",
    "adguard-dns.com": "AdGuard",
    "cleanbrowsing.org": "CleanBrowsing",
    "nextdns.io": "NextDNS",
    "doh.pub": "DNSPod",
    "alidns.com": "AliDNS",
    "dns.sb": "DNS.SB",
}

#: Well-known resolver addresses. A connection to one of these on the DoH
#: (443) or DoT (853) port is encrypted DNS; on 53 it is ordinary cleartext
#: DNS, which the tool already reads, so the port gate matters.
RESOLVER_IPS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
}


def classify_encrypted_dns(sni: str, ip: str,
                           dport) -> Optional[Tuple[str, str, str]]:
    """(provider, protocol, basis) if this looks like encrypted DNS, else None.

    `protocol` is "DoH" or "DoT"; `basis` names what matched (the SNI, or the
    resolver address on its port), so the reader sees the evidence. The SNI
    is the strong signal and is trusted on any port; a resolver IP is trusted
    only on 443 (DoH) or 853 (DoT), never on 53 — that is plain DNS the tool
    already reads.
    """
    try:
        port = int(dport) if dport is not None and str(dport) != "" else None
    except (TypeError, ValueError):
        port = None

    if sni:
        host = sni.lower().rstrip(".")
        for suffix, provider in DOH_HOST_SUFFIXES.items():
            if host == suffix or host.endswith("." + suffix):
                proto = "DoT" if port == 853 else "DoH"
                return provider, proto, f"SNI {sni}"

    provider = RESOLVER_IPS.get(ip)
    if provider:
        if port == 443:
            return provider, "DoH", f"{ip} on 443"
        if port == 853:
            return provider, "DoT", f"{ip} on 853"
    return None
