"""The HTML report — the same text, wrapped, with the glossary on hover.

The constraint under test is the one the module is built around: the page
contains the terminal renderer's EXACT text (adding a second rendering
implementation would let the kept file disagree with what the operator
saw). On top of that: escaping is airtight even when the capture contains
markup, each glossary term is wrapped once at first occurrence and linked
to a full definition that is present, section rules become navigation, and
the file is self-contained — no script tags, no external URLs.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from out.html import render_html


_SAMPLE = """\
── WHAT THIS CAPTURE SHOWS ─────────────────────────────────────────────

  90% of answered DNS lookups failed (NXDOMAIN). A beacon with high
  periodicity was measured. NXDOMAIN again, and more DNS.

── CONNECTIONS ─────────────────────────────────────────────────────────
      3  refused — reset without ever being answered
"""


def _strip_tags(page: str) -> str:
    import html as html_mod
    # Tooltip bodies are markup the wrapper ADDED inside a line; remove them
    # before stripping tags, or the comparison sees definition text spliced
    # into the report's sentences.
    text = re.sub(r'<span class="tip">.*?</span>', "", page, flags=re.S)
    text = re.sub(r"<[^>]+>", "", text)
    return html_mod.unescape(text)


# --------------------------------------------------------------------------
# the text survives intact
# --------------------------------------------------------------------------


def test_every_line_of_the_report_survives_verbatim():
    page = render_html(_SAMPLE, source_name="t.pcap")
    flat = " ".join(_strip_tags(page).split())
    for line in _SAMPLE.splitlines():
        if line.strip():
            assert " ".join(line.split()) in flat, line


def test_markup_in_the_capture_is_escaped_not_executed():
    hostile = ('── CAPTURE ─────\n  qname <script>alert(1)</script> '
               "<img src=x onerror=y> & friends\n")
    page = render_html(hostile)
    assert "<script>" not in page
    assert "<img" not in page
    assert "&lt;script&gt;" in page
    # ...and the content is still readable after unescaping
    assert "<script>alert(1)</script>" in _strip_tags(page)


# --------------------------------------------------------------------------
# tooltips
# --------------------------------------------------------------------------


def test_terms_are_wrapped_once_at_first_occurrence():
    page = render_html(_SAMPLE)
    # NXDOMAIN appears twice in the sample; exactly one wrap.
    assert page.count('href="#def-nxdomain"') == 1
    assert 'class="term"' in page
    # the tooltip carries the short definition
    assert "name does not exist" in page


def test_each_wrapped_term_has_its_full_definition_present():
    page = render_html(_SAMPLE)
    for anchor in re.findall(r'href="#(def-[a-z0-9-]+)"', page):
        assert f'id="{anchor}"' in page, anchor
    # the full-entry text, not merely the heading
    assert "resolver appending a search-domain suffix" in page


def test_definitions_block_carries_the_not_findings_disclaimer():
    page = render_html(_SAMPLE)
    assert "Definitions, not findings" in page


def test_no_terms_no_definitions_block():
    page = render_html("── CAPTURE ─────\n  nothing jargon-like here\n")
    assert "Terms used in this report" not in page


# --------------------------------------------------------------------------
# navigation and self-containment
# --------------------------------------------------------------------------


def test_section_rules_become_navigation():
    page = render_html(_SAMPLE)
    assert 'id="what-this-capture-shows"' in page
    assert 'href="#what-this-capture-shows"' in page
    assert 'href="#connections"' in page


def test_page_is_self_contained():
    page = render_html(_SAMPLE)
    assert "<script" not in page.lower()
    assert "http://" not in page
    assert "https://" not in page
    assert "@import" not in page
    assert 'src="' not in page


# --------------------------------------------------------------------------
# CLI end to end
# --------------------------------------------------------------------------


def test_cli_writes_the_page():
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    with tempfile.TemporaryDirectory() as d:
        pcap = Path(d) / "suspect.pcap"
        page = Path(d) / "report.html"
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "make_test_pcap.py"),
             str(pcap), "--profile", "suspect"],
            env=env, capture_output=True, text=True)
        run = subprocess.run(
            [sys.executable, str(ROOT / "semantiq.py"), "read", str(pcap),
             "--html", str(page), "--no-inventory"],
            env=env, capture_output=True, text=True)
        assert run.returncode == 0, run.stderr
        assert page.exists()
        content = page.read_text()
    assert "<!DOCTYPE html>" in content
    assert "ENDPOINT DETAIL" in content
    assert 'class="term"' in content          # tooltips present
    assert "wrote" in run.stderr


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
