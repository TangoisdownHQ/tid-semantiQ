"""Who an address belongs to — from datasets on disk, nothing live.

An IP address is the least meaningful name a report can print, and most of a
capture's endpoints have nothing better unless a lookup happened on the
wire. This module adds the next layer of meaning OFFLINE: given datasets the
operator already has on disk, an address becomes "AS13335 CLOUDFLARENET
(US)" or "AWS us-east-1, EC2" — which organisation announces it, and which
cloud it sits in.

OFFLINE IS A FEATURE, NOT A LIMITATION. This tool analyses captures that
routinely contain indicators of compromise, and resolving those against a
live service tells the service — and anyone watching your DNS — exactly
what you are investigating. A dataset on disk leaks nothing, works in an
air-gapped lab, and gives the same answer tomorrow that it gave today,
which is what makes a report reproducible.

NOTHING IS BUNDLED, by the same reasoning as the rest of the repo's
third-party policy: these datasets are large, they go stale monthly, and
their licences are their own. The operator points at files they fetched:

  --enrich-asn    an IP-to-ASN TSV in the common five-column layout
                  (range_start, range_end, AS number, country, AS name) —
                  the format published at iptoasn.com, among others
  --enrich-cloud  a cloud provider's published range file, auto-detected:
                  AWS ip-ranges.json, GCP cloud.json, or an Azure
                  ServiceTags download. Repeatable, one per provider.

Everything degrades to silence: no files, no lookups, no changed report —
and `describe()` says what was loaded so the report can state its sources.

Attribution honesty: an ASN names who ANNOUNCES the route, and a cloud
range names the LANDLORD, not the tenant. An address in AWS's ranges is
"in AWS", never "is Amazon" — the narrator's wording keeps that distinction,
and this module's job is only to supply the facts that make it possible.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

__all__ = ["Enrichment", "Enricher"]


class Enrichment(NamedTuple):
    asn: Optional[int] = None
    as_name: Optional[str] = None
    country: Optional[str] = None
    provider: Optional[str] = None   # "AWS", "GCP", "Azure"
    region: Optional[str] = None
    service: Optional[str] = None

    @property
    def empty(self) -> bool:
        return all(value is None for value in self)


def _open_maybe_gz(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


class _RangeIndex:
    """Sorted, non-overlapping-enough integer ranges with binary search.

    Ranges from real datasets occasionally overlap (an Azure service tag is
    not a partition); `find` returns the candidate whose start is nearest
    below the address and whose end covers it, which for these datasets is
    the most specific practical answer without building an interval tree.
    """

    def __init__(self) -> None:
        self._rows: List[Tuple[int, int, Any]] = []
        self._starts: List[int] = []

    def add(self, low: int, high: int, data: Any) -> None:
        self._rows.append((low, high, data))

    def freeze(self) -> None:
        self._rows.sort(key=lambda r: (r[0], r[1]))
        self._starts = [row[0] for row in self._rows]

    def find(self, value: int) -> Optional[Any]:
        index = bisect.bisect_right(self._starts, value) - 1
        # Walk back over earlier-starting ranges until one covers the value;
        # bounded walk, because real datasets nest only a few levels deep.
        for _ in range(8):
            if index < 0:
                return None
            low, high, data = self._rows[index]
            if low <= value <= high:
                return data
            index -= 1
        return None

    def __len__(self) -> int:
        return len(self._rows)


class Enricher:
    def __init__(self) -> None:
        self._asn4 = _RangeIndex()
        self._asn6 = _RangeIndex()
        self._cloud4 = _RangeIndex()
        self._cloud6 = _RangeIndex()
        #: MAC-prefix -> vendor, keyed by prefix length in hex digits so a
        #: longer (more specific) MA-M/MA-S assignment wins over the 24-bit
        #: block it sits inside. {6: {...}, 7: {...}, 9: {...}}.
        self._oui: Dict[int, Dict[str, str]] = {}
        self.sources: List[str] = []

    # -- loading -----------------------------------------------------------

    def load_asn_tsv(self, path: Path | str) -> int:
        """The five-column IP-to-ASN TSV. Returns rows loaded."""
        path = Path(path)
        rows = 0
        with _open_maybe_gz(path) as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                try:
                    low = int(ipaddress.ip_address(parts[0]))
                    high = int(ipaddress.ip_address(parts[1]))
                    asn = int(parts[2])
                except ValueError:
                    continue
                if asn == 0:        # the dataset's "not routed" marker
                    continue
                data = (asn, parts[4].strip(), parts[3].strip() or None)
                index = self._asn6 if ":" in parts[0] else self._asn4
                index.add(low, high, data)
                rows += 1
        self._asn4.freeze()
        self._asn6.freeze()
        self.sources.append(f"ASN: {path.name} ({rows:,} ranges)")
        return rows

    def load_cloud_json(self, path: Path | str) -> int:
        """A cloud provider's published range file, shape auto-detected."""
        path = Path(path)
        with _open_maybe_gz(path) as handle:
            document = json.load(handle)

        loaded = 0
        if isinstance(document, dict) and "values" in document:
            loaded = self._load_azure(document)
            provider = "Azure"
        elif isinstance(document, dict) and (
                "prefixes" in document or "ipv6_prefixes" in document):
            sample = (document.get("prefixes") or
                      document.get("ipv6_prefixes") or [{}])[0]
            if "ipv4Prefix" in sample or "ipv6Prefix" in sample:
                loaded = self._load_gcp(document)
                provider = "GCP"
            else:
                loaded = self._load_aws(document)
                provider = "AWS"
        else:
            raise ValueError(
                f"{path.name}: not a recognised cloud range file (expected "
                "AWS ip-ranges.json, GCP cloud.json, or Azure ServiceTags)")
        self._cloud4.freeze()
        self._cloud6.freeze()
        self.sources.append(f"{provider}: {path.name} ({loaded:,} prefixes)")
        return loaded

    def _add_cloud(self, prefix: str, provider: str,
                   region: Optional[str], service: Optional[str]) -> bool:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return False
        index = self._cloud6 if network.version == 6 else self._cloud4
        index.add(int(network.network_address),
                  int(network.broadcast_address),
                  (provider, region or None, service or None))
        return True

    def _load_aws(self, document: Dict) -> int:
        count = 0
        for row in document.get("prefixes", []):
            if self._add_cloud(row.get("ip_prefix", ""), "AWS",
                               row.get("region"), row.get("service")):
                count += 1
        for row in document.get("ipv6_prefixes", []):
            if self._add_cloud(row.get("ipv6_prefix", ""), "AWS",
                               row.get("region"), row.get("service")):
                count += 1
        return count

    def _load_gcp(self, document: Dict) -> int:
        count = 0
        for row in document.get("prefixes", []):
            prefix = row.get("ipv4Prefix") or row.get("ipv6Prefix") or ""
            if self._add_cloud(prefix, "GCP", row.get("scope"),
                               row.get("service")):
                count += 1
        return count

    def _load_azure(self, document: Dict) -> int:
        count = 0
        for value in document.get("values", []):
            properties = value.get("properties", {})
            region = properties.get("region") or None
            service = properties.get("systemService") or value.get("name")
            for prefix in properties.get("addressPrefixes", []):
                if self._add_cloud(prefix, "Azure", region, service):
                    count += 1
        return count

    def load_oui_manuf(self, path: Path | str) -> int:
        """Wireshark's `manuf` file (or IEEE oui.csv): MAC prefix -> vendor.

        The `manuf` format is `prefix<ws>short[<ws>long]`, prefix either a
        24-bit `XX:XX:XX` or a longer `XX:XX:XX:XX:XX:XX/NN` for the smaller
        MA-M (28-bit) and MA-S (36-bit) blocks. The long name wins when
        present; the short name is the fallback. A leading-# comment and the
        occasional blank line are skipped.
        """
        path = Path(path)
        rows = 0
        with _open_maybe_gz(path) as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t") if "\t" in line else line.split(None, 2)
                if len(parts) < 2:
                    continue
                prefix, short = parts[0], parts[1]
                vendor = parts[2].strip() if len(parts) >= 3 else short.strip()
                digits = self._oui_key(prefix)
                if digits is None:
                    continue
                key, length = digits
                self._oui.setdefault(length, {})[key] = vendor
                rows += 1
        self.sources.append(f"OUI: {path.name} ({rows:,} prefixes)")
        return rows

    @staticmethod
    def _oui_key(prefix: str):
        """Normalise a manuf prefix to (hex-digits, length) or None.

        `00:1B:C5:00:00:00/36` -> ("001bc5000", 9); `00:00:0C` -> ("00000c", 6).
        """
        prefix = prefix.strip()
        bits = 24
        if "/" in prefix:
            prefix, _, bitstr = prefix.partition("/")
            try:
                bits = int(bitstr)
            except ValueError:
                return None
        hexonly = prefix.replace(":", "").replace("-", "").replace(".", "").lower()
        length = bits // 4
        if length <= 0 or length > len(hexonly):
            return None
        return hexonly[:length], length

    def lookup_mac(self, mac: str) -> Optional[str]:
        """Vendor for a MAC, matching the most specific prefix loaded.

        A locally-administered or multicast MAC (the low bit of the first
        octet set, or the universal/local bit) names no vendor — randomised
        privacy MACs live here — so it returns None rather than a wrong name.
        """
        if not self._oui:
            return None
        hexonly = mac.replace(":", "").replace("-", "").replace(".", "").lower()
        if len(hexonly) < 6:
            return None
        try:
            first_octet = int(hexonly[:2], 16)
        except ValueError:
            return None
        # Bit 1 of the first octet = locally administered (randomised MAC);
        # bit 0 = multicast. Neither carries a manufacturer OUI.
        if first_octet & 0x02 or first_octet & 0x01:
            return None
        for length in sorted(self._oui, reverse=True):   # longest match wins
            vendor = self._oui[length].get(hexonly[:length])
            if vendor is not None:
                return vendor
        return None

    # -- lookup ------------------------------------------------------------

    @property
    def loaded(self) -> bool:
        return bool(self.sources)

    def describe(self) -> str:
        return "; ".join(self.sources)

    def lookup(self, address: str) -> Optional[Enrichment]:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        # Private, loopback and link-local space is nobody's announcement;
        # a dataset row covering it (some do) would attribute a LAN printer
        # to whoever squats the range in the file.
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return None
        value = int(ip)
        v6 = ip.version == 6
        asn_hit = (self._asn6 if v6 else self._asn4).find(value)
        cloud_hit = (self._cloud6 if v6 else self._cloud4).find(value)
        if asn_hit is None and cloud_hit is None:
            return None
        asn, as_name, country = asn_hit if asn_hit else (None, None, None)
        provider, region, service = cloud_hit if cloud_hit else (None, None, None)
        return Enrichment(asn=asn, as_name=as_name, country=country,
                          provider=provider, region=region, service=service)
