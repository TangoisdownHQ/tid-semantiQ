"""The Wireshark Lua integration — annotations the plugin only looks up.

Two artefacts under test. The EXPORTER must parse every display-filter
shape the findings actually emit (including the truncation comment), count
what it cannot annotate rather than hide it, and write hostile titles as
inert Lua strings. The PLUGIN FILE is Lua that Python cannot execute, so it
is checked structurally — the API calls it must make, the pure-data guard
it promises — and syntax-checked with a real Lua when one is on PATH.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.model import Channel, Entity, Evidence, Finding, Severity
from out.wiresharklua import parse_display_filter, write_lua_annotations


def _finding(rule_id: str, display_filter: str, title: str = "t",
             severity=Severity.HIGH, confidence: float = 0.8) -> Finding:
    channel = Channel(
        domain="net", dims={"proto": "tcp", "dport": "443"},
        initiator=Entity("ip", "10.0.0.5"),
        responder=Entity("ip", "203.0.113.9"),
    )
    return Finding(
        rule_id=rule_id, title=title, channel=channel, severity=severity,
        confidence=confidence,
        evidence=Evidence(channel=channel, series_count=0,
                          window=(0.0, 0.0), results=(), inspections=()),
        display_filter=display_filter,
    )


# --------------------------------------------------------------------------
# filter parsing: every shape the findings emit
# --------------------------------------------------------------------------


def test_every_emitted_filter_shape_parses():
    assert parse_display_filter("tcp.stream eq 16") == ("tcp_stream", [16])
    assert parse_display_filter("frame.number == 7") == ("frame", [7])
    assert parse_display_filter("frame.number in {1,2,3}") == \
        ("frame", [1, 2, 3])


def test_truncation_comment_is_stripped():
    text = "frame.number in {1,2,3}  # first 40 of 53 frames"
    assert parse_display_filter(text) == ("frame", [1, 2, 3])


def test_unknown_shapes_return_none():
    assert parse_display_filter("http.host == \"x\"") is None
    assert parse_display_filter("udp.stream eq 3") is None
    assert parse_display_filter("") is None


# --------------------------------------------------------------------------
# the exporter
# --------------------------------------------------------------------------


def _write(findings):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "a.lua"
        counts = write_lua_annotations(path, findings, source_name="t.pcap")
        return counts, path.read_text()


def test_streams_and_frames_land_in_their_buckets():
    (annotated, skipped), text = _write([
        _finding("net.beacon", "tcp.stream eq 16"),
        _finding("dns.tunnel", "frame.number in {1,2}"),
    ])
    assert (annotated, skipped) == (2, 0)
    assert "by_tcp_stream" in text and "[16] =" in text
    assert "by_frame" in text and "[1] =" in text and "[2] =" in text
    assert 'rule = "net.beacon"' in text
    assert 'severity = "HIGH"' in text
    assert "confidence = 0.80" in text
    assert 'source = "t.pcap"' in text
    # the capture filter travels with each finding for the plugin's summary
    assert 'bpf = "host 10.0.0.5 and host 203.0.113.9 and tcp port 443"' in text


def test_unannotatable_findings_are_counted_not_hidden():
    (annotated, skipped), text = _write([
        _finding("net.beacon", "tcp.stream eq 1"),
        _finding("http.weird", "http.host == \"x\""),   # unparseable shape
        _finding("har.only", ""),                        # no filter at all
    ])
    assert annotated == 1 and skipped == 2
    assert "http.weird" not in text and "har.only" not in text


def test_hostile_title_is_an_inert_lua_string():
    """Titles can embed capture-derived values; a quote or backslash must
    not escape the string literal and become code."""
    evil = 'x"}; os.execute("rm -rf /"); --\\\nz'
    _counts, text = _write([_finding("r", "tcp.stream eq 1", title=evil)])
    # the dangerous characters are escaped in the output
    assert '\\"' in text and "\\\\" in text and "\\n" in text
    # no raw newline inside any string literal, and the file still has the
    # pure-data first line the plugin's guard requires
    first_code = next(l for l in text.splitlines() if l and
                      not l.startswith("--"))
    assert first_code == "return {"


def test_two_findings_on_one_stream_share_the_entry():
    _counts, text = _write([
        _finding("a.rule", "tcp.stream eq 5"),
        _finding("b.rule", "tcp.stream eq 5"),
    ])
    match = re.search(r"\[5\] = \{ (.+) \},", text)
    assert match and "a.rule" in match.group(1) and "b.rule" in match.group(1)


def test_lua_syntax_when_an_interpreter_is_available():
    lua = next((t for t in ("luac", "luac5.4", "luac5.3", "lua", "lua5.4")
                if shutil.which(t)), None)
    if lua is None:
        print("        (no lua on PATH — syntax check skipped)")
        return
    _counts, text = _write([
        _finding("net.beacon", "tcp.stream eq 16",
                 title='quote " backslash \\ done'),
        _finding("dns.tunnel", "frame.number in {1,2,3}"),
    ])
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "a.lua"
        path.write_text(text)
        if lua.startswith("luac"):
            check = subprocess.run([lua, "-p", str(path)],
                                   capture_output=True, text=True)
        else:
            check = subprocess.run(
                [lua, "-e", f'assert(type(dofile("{path}")) == "table")'],
                capture_output=True, text=True)
        assert check.returncode == 0, check.stderr


# --------------------------------------------------------------------------
# the plugin file: structural checks on the Lua Python cannot run
# --------------------------------------------------------------------------


def test_plugin_makes_the_api_calls_it_must():
    plugin = (ROOT / "wireshark" / "semantiq.lua").read_text()
    assert 'Proto("semantiq"' in plugin
    assert "register_postdissector(proto)" in plugin
    for field in ("semantiq.rule", "semantiq.title", "semantiq.severity",
                  "semantiq.confidence"):
        assert field in plugin, field
    assert 'Field.new("tcp.stream")' in plugin
    assert "SEMANTIQ_ANNOTATIONS" in plugin
    # the pure-data guard the README promises
    assert 'trimmed == "return {"' in plugin
    # GUI extras are gated so tshark -X lua_script still works headless
    assert "gui_enabled()" in plugin


def test_plugin_syntax_when_an_interpreter_is_available():
    lua = next((t for t in ("luac", "luac5.4", "luac5.3")
                if shutil.which(t)), None)
    if lua is None:
        print("        (no luac on PATH — syntax check skipped)")
        return
    check = subprocess.run(
        [lua, "-p", str(ROOT / "wireshark" / "semantiq.lua")],
        capture_output=True, text=True)
    assert check.returncode == 0, check.stderr


# --------------------------------------------------------------------------
# CLI end to end
# --------------------------------------------------------------------------


def test_cli_writes_annotations_for_the_suspect_capture():
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    with tempfile.TemporaryDirectory() as d:
        pcap = Path(d) / "suspect.pcap"
        out = Path(d) / "suspect.pcap.lua"
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "make_test_pcap.py"),
             str(pcap), "--profile", "suspect"],
            env=env, capture_output=True, text=True)
        run = subprocess.run(
            [sys.executable, str(ROOT / "semantiq.py"), "read", str(pcap),
             "--wireshark-lua", str(out), "--no-inventory",
             "--no-narrative"],
            env=env, capture_output=True, text=True)
        assert run.returncode == 0, run.stderr
        text = out.read_text()
    assert "dns.tunnel.high_cardinality_zone" in text
    assert "by_frame" in text
    assert "wrote" in run.stderr and "semantiq.lua" in run.stderr


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
