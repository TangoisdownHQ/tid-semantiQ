#!/usr/bin/env python3
"""tid-semantiQ — read a capture, interpret it, say what it noticed.

    # behavioural analysis: cadence, volume, rarity (no external tools)
    semantiq.py read capture.pcap --baseline ~/.semantiq/home.db

    # + HTTP content analysis, decrypted with your own client's TLS keys
    semantiq.py read capture.pcap --http --keylog keys.log

    # a HAR from Burp, mitmproxy or devtools — no capture or keys needed
    semantiq.py read session.har

    # outputs
    semantiq.py read capture.pcap --json findings.json --colorfilters cf

TWO ANALYSES, TWO SOURCES. The native reader (`capture/pcap.py`) handles
behaviour — timing, volume, cardinality — from metadata alone, with no
dependencies. `--http` adds a tshark-backed pass for message content, which
is where the bug-bounty findings live. They run over the same capture and
land in the same report, on separate channels.

ASSISTED MODE. `--keylog` points at an NSS keylog written by your own client
(`SSLKEYLOGFILE=keys.log` for browsers and curl, or
`SSLContext.keylog_filename` in Python). You own the client, so you have the
keys — the "cannot decrypt" constraint is a defensive one, not a bug-bounty
one.

SECRETS. Extracted tokens and cookies are masked in every output by default.
`--unsafe-show-secrets` disables that, and should be reached for about as
often as the name suggests.

LEGAL. Capture only traffic on networks you administer, or your own traffic
to an authorized target. Monitor-mode Wi-Fi and RF capture reach third-party
communications and are governed by different law; neither has a plugin here.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Iterator, List

from capture.base import group_into_series
from capture.pcap import PcapSource
from core.baseline import NullBaseline, SqliteBaseline
from core.model import Context, Observation
from core.redact import passthrough, redact_secrets
from core.score import run
from ontology import ONTOLOGIES
from out import collect_advisories
from out.inventory import build_inventory, render_inventory
from out.narrate import narrate
from out.report import render
from out.sinks import ship_to_soc, write_filters, write_json, write_wireshark


def _cap_memory(limit_mb: int) -> None:
    """Refuse to grow past `limit_mb`, so a large capture kills THIS process
    rather than letting the kernel pick a victim.

    A capture is unbounded input: a nine-hour 6.9 GB file produces far more
    channels than a synthetic fixture, and batch mode holds every one. On a
    machine with 2 GB free that is the difference between a failed analysis
    and a desktop that stops responding. Failing loudly with an instruction
    is strictly better than succeeding sometimes.
    """
    try:
        import resource
    except ImportError:          # pragma: no cover - non-POSIX
        return
    limit = limit_mb * 1024 * 1024
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    ceiling = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (ceiling, hard))
    except (ValueError, OSError):
        print(f"could not set a {limit_mb} MB memory cap", file=sys.stderr)


def cmd_read(args: argparse.Namespace) -> int:
    path = Path(args.capture)
    if not path.exists():
        print(f"no such capture: {path}", file=sys.stderr)
        return 2

    if args.max_memory_mb:
        _cap_memory(args.max_memory_mb)

    redactor = passthrough if args.unsafe_show_secrets else redact_secrets
    if args.unsafe_show_secrets:
        print(
            "WARNING  --unsafe-show-secrets: tokens and cookies will be written "
            "in the clear. Do not attach this output to a report.",
            file=sys.stderr,
        )

    # A HAR has no packets, so the behavioural pass has nothing to read and
    # the content pass needs no decryption. One source, chosen by extension.
    if path.suffix.lower() == ".har":
        return _read_har(path, args, redactor)

    # Behavioural pass: always on, no external tools.
    native = PcapSource(
        path,
        burst_gap_s=args.burst_gap,
        retain_payloads=args.retain_payloads,
    )
    sources = [native]
    stats = dict(native.stats)

    # MAVLink is the one domain with a NATIVE parser rather than a tshark
    # profile, so it is its own source rather than a profile choice.
    mavlink_source = None
    if args.mavlink:
        from capture.mavlink import MavlinkSource

        mavlink_source = MavlinkSource(path, any_port=args.mavlink_any_port)
        sources.append(mavlink_source)

    # Content pass: opt-in, needs tshark. Implied by --keylog, since supplying
    # keys and getting no content analysis would be a silent no-op.
    tshark_source = None
    if args.http or args.keylog or args.modbus or args.dnp3:
        from capture.tshark import (
            Dnp3Profile,
            HttpProfile,
            ModbusProfile,
            TsharkSource,
            TsharkUnavailable,
        )

        if args.modbus:
            profile = ModbusProfile()
        elif args.dnp3:
            profile = Dnp3Profile()
        else:
            profile = HttpProfile()
        tshark_source = TsharkSource(
            path,
            profile=profile,
            keylog=args.keylog,
            retain_payloads=True,
        )
        sources.append(tshark_source)

    def observations() -> Iterator[Observation]:
        produced = 0
        for source in sources:
            try:
                for obs in source.observations():
                    yield obs
                    produced += 1
                    if args.limit and produced >= args.limit:
                        print(
                            f"--limit {args.limit} reached; the rest of the "
                            "capture was not analysed",
                            file=sys.stderr,
                        )
                        return
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                # One source failing must not discard the other's results,
                # but it must be visible: a silent zero from the content pass
                # is indistinguishable from a capture with no HTTP in it.
                print(f"{type(source).__name__}: {exc}", file=sys.stderr)

    if args.stream:
        return _read_streaming(args, observations, redactor, sources)

    series = list(group_into_series(
        observations(), min_observations=2, min_by_domain=_pruning_floors()
    ))
    if not series:
        print("no observations — nothing in the capture could be decoded", file=sys.stderr)
        return 1

    # The content pass counts its own observations, and the native reader
    # cannot know about them. Merged here rather than inside the shared tail,
    # which has no tshark source to ask.
    stats = dict(native.stats)
    if tshark_source is not None:
        stats["http"] = tshark_source.stats["observations"]

    return _analyse_and_report(
        args, series, stats, redactor, source_name=path.name,
    )



def cmd_live(args: argparse.Namespace) -> int:
    """Capture from an interface and interpret it like any other capture.

    WHAT IS ANNOUNCED, AND WHY. Live capture reaches traffic a file does
    not, and on a shared segment that includes other people's
    communications. The tool cannot judge authorisation, so it states
    plainly what it is about to watch and for how long before it starts —
    an operator who meant a different interface finds out in time.
    """
    from capture.live import CaptureUnavailable, LiveSource, preflight

    try:
        preflight(args.iface)
    except CaptureUnavailable as error:
        print(f"{error}", file=sys.stderr)
        return 2

    if args.max_memory_mb:
        _cap_memory(args.max_memory_mb)

    redactor = passthrough if args.unsafe_show_secrets else redact_secrets

    bound = []
    if args.duration:
        bound.append(f"{args.duration:g}s")
    if args.frames:
        bound.append(f"{args.frames:,} frames")
    print(
        f"capturing on {args.iface}"
        + (f" with filter {args.filter!r}" if args.filter else "")
        + (f", stopping after {' or '.join(bound)}" if bound
           else ", until interrupted (Ctrl-C)"),
        file=sys.stderr,
    )
    if not bound:
        print("  Ctrl-C stops the capture and reports what was seen; it "
              "does not discard it.", file=sys.stderr)

    source = LiveSource(
        iface=args.iface,
        burst_gap_s=args.burst_gap,
        retain_payloads=args.retain_payloads,
        bpf=args.filter,
        snaplen=args.snaplen,
        duration=args.duration,
        max_frames=args.frames,
        tool=args.tool,
    )

    def observations():
        try:
            yield from source.observations()
        except CaptureUnavailable as error:
            print(f"\ncapture failed: {error}", file=sys.stderr)

    if args.stream:
        # Continuous mode: windows close and report as the capture runs,
        # which is what a long live session wants. Equivalent to replaying
        # the same traffic from a file, because the windower runs on event
        # time rather than the wall clock.
        return _read_streaming(args, observations, redactor, [source])

    series = list(group_into_series(
        observations(), min_observations=2, min_by_domain=_pruning_floors()
    ))
    print(f"\n{source.describe()}", file=sys.stderr)
    if not series:
        print(
            "nothing to analyse. The interface was idle, or the filter "
            "excluded everything. On loopback, generate some traffic first "
            "(curl http://localhost, dig @127.0.0.1 ...).",
            file=sys.stderr,
        )
        return 1

    return _analyse_and_report(
        args, series, dict(source.stats), redactor,
        source_name=f"live:{args.iface}",
    )


def _analyse_and_report(args, series, stats, redactor, source_name: str) -> int:
    """Score, report and narrate a materialised series list.

    Factored out of `cmd_read` so live capture runs the identical path. A
    second copy would drift, and the one thing a live run must not do is
    interpret a capture differently from the file it could have been saved
    to — that equivalence is the only reason replaying a file is a valid
    test of streaming behaviour.
    """
    if args.baseline:
        baseline = SqliteBaseline(args.baseline)
        warm_up = None
    else:
        baseline = NullBaseline()
        warm_up = (
            "no --baseline given: rarity is unavailable, so rarity-gated rules "
            "(the beacon and exfil rules) cannot fire. Content findings are "
            "unaffected. Pass --baseline and run over known-good traffic first."
        )

    # `now` is the capture's end time, not wall-clock — see Context.now.
    capture_end = max((s.end or 0.0) for s in series)
    ctx = Context(
        now=capture_end,
        baseline=baseline,
        mode="assisted" if args.keylog else "passive",
        retain_payloads=args.retain_payloads,
        config=_tunables(args),
    )
    if args.baseline:
        warm_up = baseline.warm_up_notice(now=capture_end)

    findings, evidences = run(series, ONTOLOGIES, ctx)

    # Explanations are attached to findings before rendering, so a verified
    # narrative prints beneath the evidence that justifies it rather than in
    # a separate section the reader has to correlate by hand.
    narratives, explain_notes = _explain(args, findings, redactor)

    # Rendered once, printed and (optionally) written to HTML from the SAME
    # string — the file a reader keeps must be the text the operator saw.
    report_text = render(
        findings, evidences, narratives=narratives, warm_up=warm_up,
        stats=stats, redactor=redactor,
        advisories=list(collect_advisories(evidences)) + explain_notes)
    print(report_text)

    # Explain the ATT&CK / CWE codes the findings just cited, in the order
    # they appeared — the glossary pattern applied to findings rather than
    # prose. Gated on --glossary with the terms glossary, since both answer
    # "what does this jargon mean"; printed here, next to the findings, so a
    # --no-narrative run still gets it.
    if getattr(args, "glossary", False):
        from out.refs import reference_section
        section = reference_section(ref for f in findings for ref in f.refs)
        if section:
            print("\n".join(section))

    # The observation report, on by default. A capture that matched no rule
    # still has an answer to "what is in this file", and reporting only rule
    # hits threw away every measurement that did not cross a threshold.
    narration_text = ""
    if not args.no_narrative:
        narration_text = narrate(
            series, evidences, findings, stats=stats, redactor=redactor,
            source_name=source_name, top_n=args.top, trace=args.trace,
            glossary=getattr(args, "glossary", False),
            enricher=_build_enricher(args),
        )
        print(narration_text)

    if getattr(args, "html", None):
        from out.html import render_html
        page = render_html(report_text, narration_text,
                           source_name=source_name,
                           title=f"semantiQ — {source_name}")
        Path(args.html).write_text(page, encoding="utf-8")
        print(f"wrote {args.html} — self-contained, loads nothing remote",
              file=sys.stderr)

    if getattr(args, "investigate", 0):
        _investigate(args, series, evidences, ctx, redactor)

    if getattr(args, "explain_capture", False):
        _explain_capture(args, series, evidences, findings, stats, redactor,
                         source_name)

    # Inventory is reconnaissance output, not findings — printed after them
    # and suppressible, because on a large capture it is the longer half.
    inventory = build_inventory(series)
    if inventory.hosts and not args.no_inventory:
        print(render_inventory(inventory))

    if args.json:
        write_json(Path(args.json), findings, evidences, redactor=redactor,
                   inventory=inventory)
        print(f"\nwrote {args.json}", file=sys.stderr)
    if getattr(args, "wireshark_lua", None):
        from out.wiresharklua import write_lua_annotations
        annotated, skipped = write_lua_annotations(
            Path(args.wireshark_lua), findings, source_name=source_name)
        note = f" ({skipped} finding(s) have no packet filter)" if skipped else ""
        print(
            f"wrote {args.wireshark_lua} ({annotated} finding(s)){note} — "
            "install wireshark/semantiq.lua and point it at this file",
            file=sys.stderr,
        )
    if args.colorfilters:
        count = write_wireshark(Path(args.colorfilters), findings)
        print(
            f"wrote {args.colorfilters} ({count} rules) — copy into your "
            "Wireshark profile directory as 'colorfilters'",
            file=sys.stderr,
        )
    if args.filters:
        write_filters(Path(args.filters), findings)
        print(f"wrote {args.filters}", file=sys.stderr)
    if args.out == "soc":
        if not (args.soc_url and args.soc_key):
            print("--out soc needs --soc-url and --soc-key", file=sys.stderr)
            return 2
        sent = ship_to_soc(args.soc_url, args.soc_key, findings, host=args.soc_host)
        print(f"shipped {sent} events to {args.soc_url}", file=sys.stderr)

    return 0


def _build_enricher(args):
    """The offline enrichment datasets, or None when none were given.

    A missing or malformed file is a loud error, not a silent skip: an
    operator who passed --enrich-asn believes the report is attributed, and
    a report that quietly is not would be worse than the error.
    """
    asn_path = getattr(args, "enrich_asn", None)
    cloud_paths = getattr(args, "enrich_cloud", None) or []
    oui_path = getattr(args, "enrich_oui", None)
    if not asn_path and not cloud_paths and not oui_path:
        return None
    from core.enrich import Enricher
    enricher = Enricher()
    if asn_path:
        enricher.load_asn_tsv(asn_path)
    for path in cloud_paths:
        enricher.load_cloud_json(path)
    if oui_path:
        enricher.load_oui_manuf(oui_path)
    return enricher


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two captures: what is new, gone, grown, and newly findable.

    Both files go through the identical pipeline as `read` — a diff computed
    by a second implementation would diff the implementations. The baseline
    is read but never written (`record=False`): diffing a pair of files must
    not alter the rarity history the next real run depends on.
    """
    from out.diff import profile, render_diff

    if args.max_memory_mb:
        _cap_memory(args.max_memory_mb)

    profiles = []
    for role, name in (("reference", args.reference), ("capture", args.capture)):
        path = Path(name)
        if not path.exists():
            print(f"no such {role}: {path}", file=sys.stderr)
            return 2
        source = PcapSource(path, burst_gap_s=args.burst_gap)
        series = list(group_into_series(source.observations()))
        if not series:
            print(f"{role} {path.name}: no analysable channels", file=sys.stderr)
            profiles.append(profile(path.name, [], []))
            continue
        ctx = Context(
            now=max((s.end or 0.0) for s in series),
            baseline=(SqliteBaseline(args.baseline) if args.baseline
                      else NullBaseline()),
            mode="passive",
            config=_tunables(args),
        )
        findings, _evidences = run(series, ONTOLOGIES, ctx, record=False)
        profiles.append(profile(path.name, series, findings))

    print(render_diff(profiles[0], profiles[1], top_n=args.top))
    if not args.baseline:
        print(
            "\nnote: no --baseline, so rarity-gated rules could not fire in "
            "either capture; the finding comparison covers content rules "
            "only.",
            file=sys.stderr,
        )
    return 0


def _read_streaming(args: argparse.Namespace, observations, redactor,
                    sources=()) -> int:
    """Replay a capture through the sliding windower.

    The point is not speed — it is that this produces exactly what a live run
    would, because the windower is driven by event time rather than
    wall-clock. Replaying a file is therefore the only way to test streaming
    behaviour, and the only way to see it without attaching to an interface.

    The baseline is NOT written in this mode: a sliding window re-emits the
    same observations every window, so recording each emission would multiply
    a channel's history by the number of windows it survived. Warm the
    baseline with a batch pass first.
    """
    from capture.window import SlidingWindower
    from out.stream import FindingAggregator

    baseline = SqliteBaseline(args.baseline) if args.baseline else NullBaseline()
    windower = SlidingWindower(
        window_s=args.window,
        emit_every_s=args.emit_every,
        max_channels=args.max_channels,
        max_per_channel=args.max_per_channel,
    )
    aggregator = FindingAggregator()

    for batch in windower.feed_windows(observations()):
        aggregator.begin_window()
        # Event time again: the context clock is the window's own latest
        # observation, never `time.time()`.
        now = max((s.end or 0.0) for s in batch)
        ctx = Context(
            now=now,
            baseline=baseline,
            mode="assisted" if args.keylog else "passive",
            retain_payloads=args.retain_payloads,
            config=_tunables(args),
        )
        findings, evidences = run(batch, ONTOLOGIES, ctx, record=False)
        aggregator.add(findings, evidences)

    if not aggregator.windows:
        print("no windows closed — the capture is shorter than --emit-every",
              file=sys.stderr)
        return 1

    advisories = collect_advisories(aggregator.evidences())
    advisories += aggregator.notes()
    for warning in (windower.undersized_window(), windower.pressure()):
        if warning:
            advisories.append(warning)

    report = render(
        aggregator.findings(), aggregator.evidences(),
        redactor=redactor, advisories=advisories,
        warm_up=(
            f"streaming: {aggregator.windows} window(s) of {args.window:g}s, "
            f"emitted every {args.emit_every:g}s. The baseline is not written "
            "in this mode — warm it with a batch pass."
        ),
        # Real counters from the sources, not zeros. Reporting "0 tcp" on a
        # TCP capture reads as a decoding failure.
        stats=_merged_stats(sources, windower.stats["observations"]),
    )
    print(report)

    # How each finding behaved across windows is the extra information
    # streaming buys, and it is not a finding itself.
    cross_window: List[str] = []
    streamed = [e for e in aggregator.streamed() if aggregator.windows > 1]
    if streamed:
        cross_window.append(f"\nacross {aggregator.windows} windows:")
        for entry in streamed:
            shape = "persistent" if entry.persistent else "TRANSIENT"
            trend = " confidence rose" if entry.strengthened else ""
            cross_window.append(
                f"  {entry.finding.rule_id:<46} "
                f"{entry.windows_seen}/{aggregator.windows} windows  "
                f"{shape}{trend}"
            )
    for line in cross_window:
        print(line)

    # Streaming has no full narration to scan, so the glossary reads the
    # findings report and the cross-window summary — which is where the
    # windowing vocabulary (sliding window, persistent/TRANSIENT, load
    # shedding) actually appears, alongside the shared behavioural terms.
    if getattr(args, "glossary", False):
        from out.glossary import glossary_section
        from out.refs import reference_section
        refs = reference_section(
            ref for f in aggregator.findings() for ref in f.refs)
        if refs:
            print("\n".join(refs))
        section = glossary_section(report + "\n" + "\n".join(cross_window))
        if section:
            print("\n".join(section))

    if args.json:
        write_json(Path(args.json), aggregator.findings(),
                   aggregator.evidences(), redactor=redactor)
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


def _read_har(path: Path, args: argparse.Namespace, redactor) -> int:
    """HAR path: content analysis only.

    Kept as its own function rather than bolted into the pcap flow, because
    almost nothing is shared — no burst assembly, no behavioural primitives,
    no keylog, and loci that cannot produce a Wireshark filter.
    """
    from capture.har import HarSource

    source = HarSource(path, retain_bodies=True)
    try:
        series = list(group_into_series(
            source.observations(), min_observations=2,
            min_by_domain=_pruning_floors(),
        ))
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not series:
        print("no usable entries in the HAR", file=sys.stderr)
        return 1

    baseline = SqliteBaseline(args.baseline) if args.baseline else NullBaseline()
    ctx = Context(
        now=max((s.end or 0.0) for s in series),
        baseline=baseline,
        mode="assisted",      # a HAR is already plaintext
        config=_tunables(args),
    )
    findings, evidences = run(series, ONTOLOGIES, ctx)

    print(render(
        findings, evidences, redactor=redactor,
        stats={
            "frames": source.stats["entries"], "decoded": source.stats["entries"],
            "tcp": 0, "udp": 0, "dns": 0,
        },
        warm_up=(
            "HAR input: no packet timing, so behavioural rules (beaconing, "
            "exfil shape) cannot fire. Content findings are unaffected."
        ),
        advisories=collect_advisories(evidences),
    ))

    inventory = build_inventory(series)
    if inventory.hosts and not args.no_inventory:
        print(render_inventory(inventory))

    if args.json:
        write_json(Path(args.json), findings, evidences, redactor=redactor,
                   inventory=inventory)
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


def _pruning_floors() -> dict:
    """Domains where a SINGLE observation can still be a finding.

    Derived from the inspector registry rather than hardcoded, so adding
    inspectors to a domain automatically stops its singletons being pruned.

    The two kinds of domain need opposite answers. A behaviour-only channel
    with one observation can say nothing, so pruning it is pure gain —
    measured on 20 minutes of real browsing, 97% of DNS channels held fewer
    than six observations and could never support a cadence finding. But one
    injected MAVLink disarm is a single message on its own channel, and it is
    the most serious thing the tool detects.

    The CLI previously passed `min_observations=1` for everything, which
    defeated the pruning `group_into_series` exists to do.
    """
    from inspectors import INSPECTOR_STACKS

    return {domain: 1 for domain, stack in INSPECTOR_STACKS.items() if stack}


def _merged_stats(sources, observations: int) -> dict:
    merged = {"frames": 0, "decoded": 0, "tcp": 0, "udp": 0, "dns": 0}
    for source in sources:
        for key, value in getattr(source, "stats", {}).items():
            if key in merged and isinstance(value, int):
                merged[key] += value
    if not merged["frames"]:
        merged["frames"] = merged["decoded"] = observations
    return merged


def _explain(args, findings, redactor):
    """Optional model-written explanations. Returns (narratives, notes).

    EVERY failure path returns computed-only output. A backend that is down,
    a model that answers with prose instead of JSON, a narrative citing a
    measurement that does not exist — all of them end here with a note in
    the advisories and the report unchanged. The analysis never depends on
    the model being available, which is what makes it safe to default the
    flag off and safe to turn on.
    """
    if not getattr(args, "explain", False) or not findings:
        return {}, []

    from agents import LLMError, REMOTE_PROVIDERS, build, explain_findings
    from out.report import _coalesce

    # Explain what will actually be PRINTED. The report collapses findings
    # that share a rule and a host, and only the group lead is rendered — so
    # explaining `findings[:limit]` spent model calls on findings nobody
    # would see and attached narratives to ids the renderer never looks up.
    # The symptom was a verified explanation that silently failed to appear.
    leads = [lead for lead, _siblings in _coalesce(findings)]

    notes = []
    if args.llm_provider in REMOTE_PROVIDERS:
        # Said once, plainly. A capture carries hostnames, SNIs and DNS
        # names that cannot be redacted because they are the subject matter;
        # sending them to a hosted model is a disclosure decision.
        notes.append(
            f"--llm-provider {args.llm_provider} sends prompts OFF this "
            f"machine. Declared secrets are redacted first, but hostnames, "
            f"SNIs and DNS names are not — they are what is being "
            f"explained. Use the default local provider for traffic you do "
            f"not own."
        )

    try:
        llm = build(
            provider=args.llm_provider,
            model=args.llm_model,
            url=args.llm_url,
            api_key=args.llm_key,
            timeout=args.llm_timeout,
        )
    except LLMError as error:
        return {}, notes + [f"explanations unavailable: {error}"]

    result = explain_findings(
        llm, leads, redactor=redactor, limit=args.explain_limit
    )
    notes.extend(result.notes())
    if result.ok:
        notes.append(
            f"{result.ok} of {min(len(leads), args.explain_limit)} "
            f"explanation(s) verified against the computed measurements "
            f"({result.model})"
        )
    return result.narratives, notes


def _investigate(args, series, evidences, ctx, redactor):
    """Level 2: model-directed measurement, printed after the findings.

    Prints the probes AND their results, including the refusals, so the
    reader can see what was asked as well as what came back. A hypothesis
    the numbers did not support is a real outcome and is labelled as one
    rather than quietly omitted.
    """
    from agents import LLMError, build, investigate
    from out.narrate import _names

    try:
        llm = build(
            provider=args.llm_provider, model=args.llm_model,
            url=args.llm_url, api_key=args.llm_key, timeout=args.llm_timeout,
        )
    except LLMError as error:
        print(f"\n  investigation unavailable: {error}", file=sys.stderr)
        return

    runs = investigate(
        llm, series, evidences, ctx, redactor=redactor,
        targets=args.investigate, names=_names(series),
    )
    if not runs:
        return

    print("\n── MODEL-DIRECTED INVESTIGATION " + "─" * 37)
    print("  The hypotheses below were written by the model; every number")
    print("  was measured by this tool after the hypothesis was committed to.")
    for run in runs:
        print("")
        for line in run.render():
            print(line)


def _explain_capture(args, series, evidences, findings, stats, redactor,
                     source_name):
    """Prose summary of the whole report, printed after the report itself.

    Order matters: the computed narration prints first and this follows it,
    so a reader meets the evidence before the paraphrase and any
    disagreement between them is visible on one screen.
    """
    from agents import LLMError, build, explain_capture
    from out.narrate import narrate

    try:
        llm = build(
            provider=args.llm_provider, model=args.llm_model,
            url=args.llm_url, api_key=args.llm_key, timeout=args.llm_timeout,
        )
    except LLMError as error:
        print(f"\n  capture summary unavailable: {error}", file=sys.stderr)
        return

    report = narrate(series, evidences, findings, stats=stats,
                     redactor=redactor, source_name=source_name,
                     top_n=args.top)
    narrative, error = explain_capture(llm, report, stats)
    if narrative is None:
        print(f"\n  capture summary unavailable: {error}", file=sys.stderr)
        return

    print("\n── IN PLAIN LANGUAGE " + "─" * 48)
    print(f"  (written by {narrative.model}; the computed report above is "
          f"the evidence)")
    for line in _wrap_text(narrative.summary):
        print(line)
    if narrative.reasoning:
        print("")
        for line in _wrap_text(narrative.reasoning):
            print(line)


def _wrap_text(text, width=70, indent="  "):
    words, lines, current = text.split(), [], indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent + word
        else:
            current = f"{current} {word}" if current.strip() else indent + word
    if current.strip():
        lines.append(current.rstrip())
    return lines


def _tunables(args: argparse.Namespace) -> dict:
    """Thresholds live in Context.config, not in code, so a deployment can
    retune without a patch."""
    config = {}
    for pair in args.set or ():
        key, _, value = pair.partition("=")
        try:
            config[key] = float(value)
        except ValueError:
            config[key] = value
    return config



def _add_shared_flags(parser: argparse.ArgumentParser) -> None:
    """Flags that mean the same thing for a file and for an interface.

    Declared here rather than via an argparse parent because a parent built
    from `read` would drag in its required `capture` positional. Kept to the
    ones that genuinely apply both ways: tshark profiles and keylogs need a
    file, so they stay on `read`.
    """
    parser.add_argument(
        "--baseline",
        help="SQLite channel-history file, for rarity",
    )
    parser.add_argument("--burst-gap", type=float, default=0.050)
    parser.add_argument("--retain-payloads", action="store_true")
    parser.add_argument("--unsafe-show-secrets", action="store_true")
    parser.add_argument("--max-memory-mb", type=int, default=2048)
    parser.add_argument(
        "--stream", action="store_true",
        help="report continuously from sliding windows instead of once at "
             "the end — for a long session",
    )
    parser.add_argument("--window", type=float, default=300.0)
    parser.add_argument("--emit-every", type=float, default=60.0)
    parser.add_argument("--max-channels", type=int, default=20000)
    parser.add_argument("--max-per-channel", type=int, default=10000)
    parser.add_argument("--no-narrative", action="store_true")
    parser.add_argument(
        "--glossary", "--explain-terms", dest="glossary", action="store_true",
        help="append plain-language definitions of the technical terms this "
             "report used — contextual (only terms that appeared), offline, "
             "and code-written, unlike the model-based --explain",
    )
    parser.add_argument("--enrich-asn", metavar="TSV")
    parser.add_argument("--enrich-cloud", metavar="JSON", action="append")
    parser.add_argument("--enrich-oui", metavar="MANUF")
    parser.add_argument("--html", metavar="PATH")
    parser.add_argument("--wireshark-lua", metavar="PATH")
    parser.add_argument("--top", type=int, default=12)
    parser.add_argument("--trace", type=int, default=0, metavar="N")
    parser.add_argument("--no-inventory", action="store_true")
    parser.add_argument("--json")
    parser.add_argument("--colorfilters")
    parser.add_argument("--filters")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--explain-capture", action="store_true")
    parser.add_argument("--explain-limit", type=int, default=10)
    parser.add_argument("--investigate", type=int, default=0, metavar="N")
    parser.add_argument("--llm-provider", default="ollama")
    parser.add_argument("--llm-model", default="")
    parser.add_argument("--llm-url", default="")
    parser.add_argument("--llm-key", default=None)
    parser.add_argument("--llm-timeout", type=float, default=180.0)
    parser.add_argument("--out", default="report", choices=("report", "soc"))
    parser.add_argument("--soc-url")
    parser.add_argument("--soc-key")
    # Default dest, because `_tunables` reads `args.set`; renaming it
    # here left the live path crashing on a flag it shares.
    parser.add_argument("--set", action="append", metavar="KEY=VALUE")
    # Flags the live path never uses but the shared analysis tail reads.
    parser.set_defaults(
        keylog=None, http=False, modbus=False, dnp3=False, mavlink=False,
        mavlink_any_port=False, limit=None,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="semantiq",
        description="read a capture, interpret it, say what it noticed",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    read = sub.add_parser("read", help="analyse a pcap/pcapng file")
    read.add_argument(
        "capture",
        help="a .pcap/.pcapng capture, or a .har exported from Burp, "
             "mitmproxy or browser devtools",
    )
    read.add_argument(
        "--baseline",
        help="SQLite channel-history file. Without it, rarity-gated rules "
             "cannot fire.",
    )
    read.add_argument(
        "--http",
        action="store_true",
        help="add a tshark-backed HTTP content pass (auth, cookies, tokens). "
             "Implied by --keylog.",
    )
    read.add_argument(
        "--modbus",
        action="store_true",
        help="add a tshark-backed Modbus/TCP pass (commands, unit and "
             "function enumeration, scan-cycle timing)",
    )
    read.add_argument(
        "--max-memory-mb", type=int, default=2048,
        help="hard ceiling on this process. Exceeding it fails the analysis "
             "with advice rather than letting the OOM killer choose a victim "
             "(default: 2048). 0 disables.",
    )
    read.add_argument(
        "--limit", type=int, default=0,
        help="analyse only the first N observations. For sampling a large "
             "capture; the truncation is reported, never silent.",
    )
    read.add_argument(
        "--stream",
        action="store_true",
        help="replay through the sliding windower instead of analysing the "
             "whole capture at once. Produces what a live run would, because "
             "the windower uses event time rather than wall-clock.",
    )
    read.add_argument(
        "--window", type=float, default=300.0,
        help="seconds of history each window carries (default: 300)",
    )
    read.add_argument(
        "--emit-every", type=float, default=60.0,
        help="seconds between window emissions (default: 60)",
    )
    read.add_argument(
        "--max-per-channel", type=int, default=10_000,
        help="observation cap per channel. On a busy link the cap binds "
             "before the time window does, narrowing the effective window — "
             "which is reported (default: 10000)",
    )
    read.add_argument(
        "--max-channels", type=int, default=20_000,
        help="channel cap before the windower sheds load; exceeding it is "
             "reported, never silent (default: 20000)",
    )
    read.add_argument(
        "--mavlink",
        action="store_true",
        help="add a MAVLink pass (command injection, position integrity). "
             "Uses a native parser — Wireshark has no MAVLink dissector.",
    )
    read.add_argument(
        "--mavlink-any-port",
        action="store_true",
        help="try every UDP datagram for MAVLink, not just the usual ports",
    )
    read.add_argument(
        "--dnp3",
        action="store_true",
        help="add a tshark-backed DNP3 pass (control commands, restarts, "
             "unsolicited-reporting suppression, address enumeration)",
    )
    read.add_argument(
        "--keylog",
        help="NSS TLS keylog from YOUR OWN client (SSLKEYLOGFILE). Enables "
             "assisted mode: tshark decrypts, and the content inspectors see "
             "plaintext. Only for your own client against an authorized target.",
    )
    read.add_argument(
        "--unsafe-show-secrets",
        action="store_true",
        help="write extracted tokens and cookies UNMASKED. Off by default so "
             "a findings file is not a credential file.",
    )
    read.add_argument(
        "--burst-gap",
        type=float,
        default=0.050,
        help="seconds; gap that closes an application-data burst. Too low "
             "fragments one message into several observations and "
             "manufactures a false cadence (default: 0.05)",
    )
    read.add_argument(
        "--retain-payloads",
        action="store_true",
        help="keep payload bytes from the native reader, for entropy "
             "analysis of cleartext protocols",
    )
    read.add_argument(
        "--no-narrative",
        action="store_true",
        help="suppress the observation report and print findings only",
    )
    read.add_argument(
        "--top", type=int, default=12,
        help="rows per ranked section in the observation report (default: 12)",
    )
    read.add_argument(
        "--trace", type=int, default=0, metavar="N",
        help="exchange-by-exchange trace of the N busiest channels: size, "
             "direction, inter-arrival gap and the activity shape they are "
             "consistent with. Works on encrypted channels — size and "
             "timing survive encryption.",
    )
    read.add_argument(
        "--no-inventory",
        action="store_true",
        help="skip the endpoint/parameter inventory section",
    )
    read.add_argument(
        "--glossary", "--explain-terms", dest="glossary", action="store_true",
        help="append plain-language definitions of the technical terms this "
             "report used — contextual (only terms that appeared), offline, "
             "and code-written. Unlike --explain, no model is involved.",
    )
    read.add_argument(
        "--enrich-asn", metavar="TSV",
        help="IP-to-ASN dataset (five-column TSV, .gz accepted) for "
             "offline 'announced by' attribution of public endpoints",
    )
    read.add_argument(
        "--enrich-cloud", metavar="JSON", action="append",
        help="a cloud provider's published range file (AWS ip-ranges.json, "
             "GCP cloud.json, or Azure ServiceTags), auto-detected; "
             "repeatable, one per provider",
    )
    read.add_argument(
        "--enrich-oui", metavar="MANUF",
        help="MAC-vendor dataset (Wireshark 'manuf' format or IEEE oui.csv, "
             ".gz accepted) to name LAN devices by their hardware vendor",
    )
    # -- model-assisted explanation (optional, off by default) ----------
    #
    # Off by default on purpose. The computed report is the product; this
    # only rephrases it. Nothing else in the tool imports `agents/`, so the
    # analysis is byte-identical whether or not a model is configured.
    read.add_argument(
        "--explain",
        action="store_true",
        help="add plain-language explanations using a language model. "
             "Every claim is checked against the computed measurements and "
             "discarded if it cites anything that was not measured.",
    )
    read.add_argument(
        "--llm-provider", default="ollama",
        help="model backend: ollama (default, local), openai (any "
             "OpenAI-compatible endpoint), huggingface, echo. "
             "Hosted backends send the prompt off this machine.",
    )
    read.add_argument(
        "--llm-model", default="",
        help="model name, e.g. qwen-abl for ollama or "
             "Qwen/Qwen2.5-7B-Instruct for huggingface",
    )
    read.add_argument(
        "--llm-url", default="",
        help="base URL for the backend; lets --llm-provider openai point at "
             "vLLM, llama.cpp, LM Studio or any compatible server",
    )
    read.add_argument(
        "--llm-key", default=None,
        help="API key. Falls back to HF_TOKEN or OPENAI_API_KEY. Never "
             "needed for a local Ollama.",
    )
    read.add_argument(
        "--llm-timeout", type=float, default=180.0,
        help="seconds to wait for the model (default: 180)",
    )
    read.add_argument(
        "--explain-limit", type=int, default=10,
        help="most findings to explain, severity-ordered (default: 10)",
    )
    read.add_argument(
        "--explain-capture",
        action="store_true",
        help="also summarise the whole observation report in prose",
    )
    read.add_argument(
        "--investigate", type=int, default=0, metavar="N",
        help="model-directed analysis of the N channels that scored highest "
             "without firing a rule. The model proposes a falsifiable "
             "hypothesis and which measurements would test it; this tool "
             "performs them and the model then judges its own hypothesis "
             "against the results. Implies a model backend.",
    )
    read.add_argument("--json", help="write findings + all channel measurements")
    read.add_argument(
        "--html", metavar="PATH",
        help="write the report as one self-contained HTML page: the same "
             "text, with section navigation and every technical term "
             "explained on hover. Loads no scripts or remote resources.",
    )
    read.add_argument(
        "--wireshark-lua", metavar="PATH",
        help="write findings as an annotations file for the bundled "
             "Wireshark plugin (wireshark/semantiq.lua): inside Wireshark, "
             "filter on semantiq.severity, add semantiq.title as a column, "
             "and read each packet's verdicts in its protocol tree",
    )
    read.add_argument("--colorfilters", help="write a Wireshark colorfilters file")
    read.add_argument("--filters", help="write plain display filters, one per line")
    read.add_argument("--out", choices=("report", "soc"), default="report")
    read.add_argument("--soc-url",
                      help="HTTP event-collector endpoint (JSON via POST)")
    read.add_argument("--soc-key", help="SOC API key")
    read.add_argument("--soc-host", default="semantiq-sensor", help="host field on SOC events")
    read.add_argument(
        "--set",
        action="append",
        metavar="KEY=VALUE",
        help="override a tunable, e.g. --set periodicity.dispersion_decay=4.0",
    )
    read.set_defaults(func=cmd_read)

    diff = sub.add_parser(
        "diff",
        help="compare two captures: new hosts, endpoints, zones, findings",
        description=(
            "Compare a capture against a reference capture. \"New\" always "
            "means present in the second file and absent from the first — a "
            "literal comparison of the two files, not a rarity judgement. "
            "The baseline, if given, is read for scoring and never written."
        ),
    )
    diff.add_argument("reference", help="the reference capture (the before)")
    diff.add_argument("capture", help="the capture to compare (the after)")
    diff.add_argument("--baseline",
                      help="SQLite channel-history file, read-only here")
    diff.add_argument("--top", type=int, default=12)
    diff.add_argument("--burst-gap", type=float, default=0.050)
    diff.add_argument("--max-memory-mb", type=int, default=2048)
    diff.add_argument("--set", action="append", metavar="KEY=VALUE")
    diff.set_defaults(func=cmd_diff)

    # `live` reuses every output and tuning flag from `read` by adding the
    # same parser twice is not possible, so the shared ones are declared
    # here deliberately rather than inherited — argparse parents would drag
    # in `capture` as a required positional.
    live = sub.add_parser(
        "live",
        help="capture from an interface and interpret it",
        description=(
            "Capture live and interpret it exactly as a file would be. "
            "Requires dumpcap or tcpdump; this tool does not capture "
            "directly and never needs root. Capture only on networks you "
            "administer, or your own traffic to an authorized target."
        ),
    )
    live.add_argument("iface", help="interface to capture on, e.g. lo")
    live.add_argument(
        "--duration", type=float, default=None, metavar="SECONDS",
        help="stop after this many seconds of wall-clock time",
    )
    live.add_argument(
        "--frames", type=int, default=None, metavar="N",
        help="stop after this many frames",
    )
    live.add_argument(
        "--filter", default="", metavar="BPF",
        help="capture filter, passed to the capture program, e.g. "
             "'tcp port 8080'",
    )
    live.add_argument(
        "--snaplen", type=int, default=262144,
        help="bytes captured per frame (default: 262144, the whole frame)",
    )
    live.add_argument(
        "--tool", default=None, choices=("dumpcap", "tcpdump"),
        help="capture program to use (default: dumpcap if present)",
    )
    _add_shared_flags(live)
    live.set_defaults(func=cmd_live)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except MemoryError:
        print(
            f"\nout of memory at the {args.max_memory_mb} MB cap.\n"
            "  This capture is too large to analyse whole. Either:\n"
            "    --stream              window it instead of buffering it all\n"
            "    --limit N             analyse the first N observations\n"
            "    --max-memory-mb M     raise the cap, if the machine has room\n"
            "  Streaming is the right answer for a multi-gigabyte capture; its\n"
            "  memory is bounded by --max-channels rather than by file size.",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    sys.exit(main())
