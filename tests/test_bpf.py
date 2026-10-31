"""Per-finding BPF capture filters.

The one thing that must hold: a BPF filter is built from the channel's
addresses and transport, never from the Wireshark display filter — a capture
filter runs in the kernel before a packet is kept and cannot speak of a TCP
stream or frame index. The rest pins the shapes (host/proto/port, DNS port by
service, IPv6), that a flowless finding is counted not dropped, dedup, and —
when a `tcpdump`/`compile` toolchain is present — that the output actually
compiles as libpcap.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.model import Channel, Entity, Evidence, Finding, Severity
from out.bpf import bpf_for_finding, write_bpf


def _finding(domain="net", dims=None, init="10.0.0.5", resp="203.0.113.9",
             rule="net.beacon.periodic_callback", title="t",
             display_filter="tcp.stream eq 16") -> Finding:
    channel = Channel(
        domain=domain, dims=dims or {"proto": "tcp", "dport": "443"},
        initiator=Entity("ip", init) if init else None,
        responder=Entity("ip", resp) if resp else None,
    )
    return Finding(
        rule_id=rule, title=title, channel=channel, severity=Severity.HIGH,
        confidence=0.82,
        evidence=Evidence(channel=channel, series_count=0, window=(0.0, 0.0),
                          results=(), inspections=()),
        display_filter=display_filter,
    )


# --------------------------------------------------------------------------
# construction
# --------------------------------------------------------------------------


def test_tcp_flow_filter_from_channel_not_display_filter():
    f = _finding(display_filter="tcp.stream eq 16")
    bpf = bpf_for_finding(f)
    assert bpf == "host 10.0.0.5 and host 203.0.113.9 and tcp port 443"
    # the untranslatable display-filter concept must not leak in
    assert "stream" not in bpf and "frame" not in bpf


def test_udp_without_port_uses_proto_only():
    f = _finding(dims={"proto": "udp"})
    assert bpf_for_finding(f) == "host 10.0.0.5 and host 203.0.113.9 and udp"


def test_dns_channel_gets_its_service_port():
    plain = _finding(domain="dns", dims={"proto": "udp", "zone": "x.test"},
                     resp="10.0.0.1")
    assert bpf_for_finding(plain).endswith("udp port 53")
    mdns = _finding(domain="dns",
                    dims={"proto": "udp", "zone": "x.local", "service": "mdns"},
                    resp="224.0.0.251")
    assert bpf_for_finding(mdns).endswith("udp port 5353")


def test_ipv6_addresses_are_emitted_as_host_terms():
    f = _finding(init="fe80::5", resp="2606:4700::1111",
                 dims={"proto": "tcp", "dport": "443"})
    bpf = bpf_for_finding(f)
    assert "host fe80::5" in bpf and "host 2606:4700::1111" in bpf


def test_single_host_when_initiator_missing():
    f = _finding(init=None, dims={"proto": "tcp", "dport": "443"})
    assert bpf_for_finding(f) == "host 203.0.113.9 and tcp port 443"


def test_no_packet_addresses_yields_no_filter():
    # a HAR-style finding: a hostname channel with no IPs
    f = _finding(init=None, resp=None, dims={"proto": "tcp"})
    assert bpf_for_finding(f) is None


def test_duplicate_host_is_not_repeated():
    f = _finding(init="10.0.0.5", resp="10.0.0.5",
                 dims={"proto": "tcp", "dport": "22"})
    assert bpf_for_finding(f) == "host 10.0.0.5 and tcp port 22"


# --------------------------------------------------------------------------
# the file
# --------------------------------------------------------------------------


def test_write_counts_and_combines():
    findings = [
        _finding(resp="203.0.113.9", rule="net.beacon"),
        _finding(resp="198.51.100.7", rule="net.exfil",
                 dims={"proto": "tcp", "dport": "8080"}),
        _finding(init=None, resp=None, dims={}, rule="http.only"),  # no flow
    ]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "f.bpf"
        produced, skipped = write_bpf(path, findings)
        text = path.read_text()
    assert (produced, skipped) == (2, 1)
    assert "host 203.0.113.9 and tcp port 443" in text
    assert "host 198.51.100.7 and tcp port 8080" in text
    # combined OR, each clause parenthesised so ORs don't bind across ANDs
    assert "# combined" in text
    assert ("(host 10.0.0.5 and host 203.0.113.9 and tcp port 443) or "
            "(host 10.0.0.5 and host 198.51.100.7 and tcp port 8080)") in text


def test_identical_channels_dedupe_in_the_combined_filter():
    findings = [_finding(rule="a"), _finding(rule="b")]   # same flow, 2 rules
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "f.bpf"
        produced, _ = write_bpf(path, findings)
        text = path.read_text()
    assert produced == 2                          # both findings are listed
    # ...but the combined expression names the shared flow only once
    combined = [l for l in text.splitlines() if l and not l.startswith("#")][-1]
    assert combined.count("host 10.0.0.5 and host 203.0.113.9") == 1
    assert " or " not in combined                 # one flow, no OR needed


def test_output_compiles_as_libpcap_when_a_compiler_is_present():
    """If tcpdump is on PATH, every emitted filter must actually compile —
    the whole value is a filter you can paste into a capture tool."""
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        print("        (no tcpdump on PATH — compile check skipped)")
        return
    exprs = [
        bpf_for_finding(_finding()),
        bpf_for_finding(_finding(dims={"proto": "udp"})),
        bpf_for_finding(_finding(domain="dns",
                                 dims={"proto": "udp", "zone": "x"},
                                 resp="10.0.0.1")),
        bpf_for_finding(_finding(init="fe80::5", resp="2606:4700::1",
                                 dims={"proto": "tcp", "dport": "443"})),
    ]
    for expr in exprs:
        # -d dumps the compiled program without needing an interface or root.
        check = subprocess.run([tcpdump, "-d", expr],
                               capture_output=True, text=True)
        assert check.returncode == 0, f"{expr!r}: {check.stderr}"


def _run_all():
    import traceback

    tests = sorted(
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    )
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
