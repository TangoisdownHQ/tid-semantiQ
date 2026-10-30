# semantiQ inside Wireshark

`semantiq.lua` is a Wireshark post-dissector that attaches tid-semantiQ's
findings to the packets they are about. Inside Wireshark you can then:

- **filter** — `semantiq` (any annotated packet),
  `semantiq.severity == "HIGH"`, `semantiq.rule contains "beacon"`
- **add a column** — right-click any `semantiq.*` field in the packet
  detail → *Apply as Column*
- **read verdicts** — select a packet and open its *tid-semantiQ* subtree:
  finding title, rule id, severity, confidence
- **Tools → tid-semantiQ** — a findings summary window, and a reload action

## Install (once)

Copy `semantiq.lua` into your personal Lua plugins directory — find it via
*Help → About Wireshark → Folders → Personal Lua Plugins*. Typically:

```bash
mkdir -p ~/.local/lib/wireshark/plugins
cp wireshark/semantiq.lua ~/.local/lib/wireshark/plugins/
```

## Use (per capture)

```bash
# 1. analyse the capture, writing annotations beside it
python3 semantiq.py read capture.pcap --wireshark-lua capture.pcap.lua

# 2. tell the plugin where the annotations are — either:
#    Edit -> Preferences -> Protocols -> SEMANTIQ -> annotations file
#    ...or the environment, before launching:
SEMANTIQ_ANNOTATIONS=capture.pcap.lua wireshark capture.pcap
```

Changed the annotations? *Tools → tid-semantiQ → Reload annotations* (or
*Analyze → Reload Lua Plugins*).

## Why the plugin holds no opinion

All analysis happens in semantiQ, which writes its verdicts to the
annotations file; the plugin only looks packets up in it, by frame number
and by TCP stream index. A Lua dissector runs per-packet and streaming,
which is structurally wrong for flow-level behavioural analysis — cadence
does not exist in any single packet — and a second implementation would
drift from the first. This way the plugin can never disagree with the
report, by construction.

Packet colouring is deliberately left to `--colorfilters`, which writes a
Wireshark `colorfilters` file — colouring rules are a profile concern in
Wireshark, not something the Lua API does well.

## Safety note

The annotations file is loaded with Lua's `dofile`, so the plugin refuses
any file whose first significant line is not exactly `return {` — the
pure-data shape the exporter writes. Treat annotations files with the same
care as the captures they describe; they contain finding titles derived
from the traffic.
