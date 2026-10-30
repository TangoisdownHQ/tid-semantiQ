"""Optional model-assisted explanation.

Entirely optional and entirely additive: nothing in `core/`, `capture/`,
`inspectors/` or `out/` imports this package, so the analysis runs
identically whether or not a model is configured. That is deliberate — the
measurements are the product, and an explanation is a convenience layered on
top of them.

See `agents/explain.py` for what a model is and is not permitted to do, and
`agents/provider.py` for why the default backend is local.
"""

from agents.explain import ExplainResult, explain_capture, explain_findings
from agents.investigate import Investigation, investigate, investigate_channel
from agents.probe import Probe, ProbeResult, describe_vocabulary, run_probe
from agents.provider import (
    PROVIDERS,
    REMOTE_PROVIDERS,
    LLM,
    LLMError,
    build,
    describe_providers,
)

__all__ = [
    "LLM", "LLMError", "build", "PROVIDERS", "REMOTE_PROVIDERS",
    "describe_providers", "explain_findings", "explain_capture",
    "ExplainResult", "Investigation", "investigate", "investigate_channel",
    "Probe", "ProbeResult", "describe_vocabulary", "run_probe",
]
