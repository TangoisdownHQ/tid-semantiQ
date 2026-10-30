"""The report as a self-contained HTML page, with the glossary on hover.

A terminal report is read once and lost to scrollback; the HTML report is
the same report as a file that can be kept, sent, and read by someone who
was not at the terminal. THE SAME REPORT is the design constraint: this
module does not re-render sections from data — it takes the exact text the
terminal renderer produced and wraps it. A second rendering implementation
would drift from the first, and then the file someone kept would disagree
with what the operator saw. Wrapping the one true text makes that
impossible by construction.

What the wrapper adds is navigation and explanation, not content:

  - a sidebar built from the report's own `── SECTION ──` rules
  - the glossary, inverted: in the terminal it is a section at the end,
    here the first occurrence of each term becomes a dashed-underlined
    span whose tooltip is the short definition and whose click lands on
    the full entry — the ideal form of "explain the terms", because the
    explanation sits exactly where the term is met
  - light and dark rendering via the reader's own preference

Self-contained on principle: no scripts, no external fonts, no CDN —
nothing in the file phones anywhere, because the report of a capture full
of indicators must be as quiet as the analysis that produced it. The
tooltips are CSS only, so the file works with JavaScript disabled.
"""

from __future__ import annotations

import html as _html
import re
from typing import Dict, List, Optional, Tuple

from out.glossary import GLOSSARY, Term

__all__ = ["render_html"]


_SECTION_RE = re.compile(r"^── ([A-Z][A-Z0-9 &'/()．.,-]*?) ─+\s*$", re.MULTILINE)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _term_spans(text: str) -> List[Tuple[int, int, Term]]:
    """(start, end, term) for the FIRST occurrence of each glossary term,
    non-overlapping, in document order.

    One wrap per term, at first sight: underlining every occurrence would
    turn the report into a sea of marks, and the reader who met the term
    once has met it.
    """
    hits: List[Tuple[int, int, Term]] = []
    for term in GLOSSARY:
        best: Optional[Tuple[int, int]] = None
        for pattern in term.triggers:
            found = pattern.search(text)
            if found and (best is None or found.start() < best[0]):
                best = (found.start(), found.end())
        if best and best[1] > best[0]:
            hits.append((best[0], best[1], term))
    hits.sort(key=lambda h: h[0])
    chosen: List[Tuple[int, int, Term]] = []
    cursor = 0
    for start, end, term in hits:
        if start >= cursor:
            chosen.append((start, end, term))
            cursor = end
    return chosen


def _mark_terms(text: str) -> Tuple[str, List[Term]]:
    """Escape `text` for HTML, wrapping each term's first occurrence.

    Escaping and wrapping happen in one walk so a trigger can never match
    inside markup this function itself inserted.
    """
    spans = _term_spans(text)
    out: List[str] = []
    cursor = 0
    for start, end, term in spans:
        out.append(_html.escape(text[cursor:start]))
        word = _html.escape(text[start:end])
        tip = _html.escape(term.short)
        anchor = _slug(term.term)
        out.append(
            f'<a class="term" href="#def-{anchor}">{word}'
            f'<span class="tip">{tip} <em>— click for the full '
            f'entry</em></span></a>'
        )
        cursor = end
    out.append(_html.escape(text[cursor:]))
    return "".join(out), [term for _s, _e, term in spans]


_STYLE = """
:root { color-scheme: light dark;
  --bg: #ffffff; --fg: #1a1a1a; --dim: #6a6a6a; --rule: #d0d0d0;
  --accent: #0a6e4f; --mark: #8a5a00; --panel: #f6f6f4; }
@media (prefers-color-scheme: dark) { :root {
  --bg: #121212; --fg: #d6d6d0; --dim: #8a8a84; --rule: #3a3a3a;
  --accent: #5fb89a; --mark: #d4a24a; --panel: #1c1c1a; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 13px/1.45 ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
.layout { display: flex; gap: 0; align-items: flex-start; }
nav { position: sticky; top: 0; flex: 0 0 15.5rem; max-height: 100vh;
  overflow-y: auto; padding: 1.2rem 1rem; border-right: 1px solid var(--rule);
  background: var(--panel); }
nav h1 { font-size: 0.95rem; margin: 0 0 .2rem; color: var(--accent); }
nav .src { color: var(--dim); font-size: .72rem; margin: 0 0 1rem;
  word-break: break-all; }
nav a { display: block; color: var(--fg); text-decoration: none;
  font-size: .76rem; padding: .14rem 0; }
nav a:hover { color: var(--accent); }
main { flex: 1 1 auto; min-width: 0; padding: 1.2rem 1.6rem 4rem; }
pre { margin: 0; white-space: pre-wrap; word-break: break-word; }
.section-title { color: var(--accent); font-weight: 700; }
a.term { color: inherit; text-decoration: underline dashed var(--mark);
  text-underline-offset: 3px; position: relative; cursor: help; }
a.term .tip { display: none; position: absolute; left: 0; bottom: 1.5em;
  z-index: 2; width: 26rem; max-width: 70vw; padding: .5rem .65rem;
  background: var(--panel); color: var(--fg); border: 1px solid var(--rule);
  border-left: 3px solid var(--mark); font-size: .76rem; white-space: normal; }
a.term .tip em { color: var(--dim); font-style: normal; }
a.term:hover .tip, a.term:focus .tip { display: block; }
.defs { margin-top: 2.5rem; border-top: 1px solid var(--rule);
  padding-top: 1rem; }
.defs h2 { color: var(--accent); font-size: .95rem; }
.defs .note { color: var(--dim); font-size: .78rem; max-width: 46rem; }
.defs dt { color: var(--mark); font-weight: 700; margin-top: 1rem; }
.defs dd { margin: .25rem 0 0 1rem; max-width: 46rem;
  font-size: .82rem; white-space: normal; }
footer { margin-top: 3rem; color: var(--dim); font-size: .72rem; }
@media (max-width: 760px) { .layout { display: block; }
  nav { position: static; max-height: none; border-right: 0;
        border-bottom: 1px solid var(--rule); } }
"""


def render_html(report: str, narration: str = "", source_name: str = "",
                title: str = "tid-semantiQ report") -> str:
    """One self-contained page from the terminal renderer's exact output."""
    body = report.rstrip()
    if narration.strip():
        body += "\n" + narration

    marked, used_terms = _mark_terms(body)

    # Section anchors, from the report's own rules. The substitution runs on
    # the MARKED text, which is safe because section-rule lines are plain
    # uppercase and never carry a term wrap in the middle.
    toc: List[Tuple[str, str]] = []

    def _anchor(match: re.Match) -> str:
        name = match.group(1).strip()
        anchor = _slug(name) or "section"
        toc.append((name, anchor))
        return (f'<span class="section-title" id="{anchor}">'
                f"{match.group(0)}</span>")

    marked = _SECTION_RE.sub(_anchor, marked)

    nav_links = "\n".join(
        f'    <a href="#{anchor}">{_html.escape(name.title())}</a>'
        for name, anchor in toc
    )

    definitions = ""
    if used_terms:
        rows = []
        for term in used_terms:
            rows.append(f'  <dt id="def-{_slug(term.term)}">'
                        f"{_html.escape(term.term)}</dt>")
            rows.append(f"  <dd>{_html.escape(term.long)}</dd>")
        definitions = (
            '<div class="defs">\n'
            "<h2>Terms used in this report</h2>\n"
            '<p class="note">Definitions, not findings — nothing here is '
            "specific to this capture, and no model wrote any of it. Each "
            "underlined term above links to its entry here.</p>\n"
            "<dl>\n" + "\n".join(rows) + "\n</dl>\n</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_html.escape(title)}</title>
<style>{_STYLE}</style>
<body>
<div class="layout">
<nav>
  <h1>{_html.escape(title)}</h1>
  <p class="src">{_html.escape(source_name)}</p>
{nav_links}
</nav>
<main>
<pre>{marked}</pre>
{definitions}
<footer>Generated by tid-semantiQ. Self-contained: this file loads no
scripts, fonts, or remote resources.</footer>
</main>
</div>
</body>
</html>
"""
