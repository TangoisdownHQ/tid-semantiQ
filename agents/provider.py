"""Model backends, behind one small interface.

THE DEFAULT IS LOCAL, AND THAT IS A SECURITY DECISION RATHER THAN A
PREFERENCE. A packet capture contains session cookies, Authorization
headers, internal hostnames and every SNI the host reached. Posting that to
a hosted API is an exfiltration event with extra steps — and this tool's
whole audience is people handling other organisations' traffic under
authorisation. So `ollama` is the default, a hosted provider is only ever
used when explicitly named, and `agents/explain.py` redacts declared secrets
before a prompt is built regardless of which backend is in use.

FOUR BACKENDS, THREE OF WHICH ARE THE SAME WIRE FORMAT:

    ollama       local, native /api/chat
    openai       anything speaking the OpenAI chat API — Ollama's own /v1,
                 llama.cpp, vLLM, LM Studio, Together, Groq, OpenAI itself
    huggingface  Inference Providers router (chat-completions compatible)
    echo         no network at all; returns a fixed structure for tests

`openai` is the extension point. Adding a new commercial endpoint almost
never needs code here — it needs a base URL and a key, which is why that
backend takes both as parameters rather than hard-coding a host.

STDLIB ONLY. `urllib.request` rather than `requests`, because `core/` and
its neighbours have no third-party dependencies and an AI feature is not a
good reason to acquire the project's first one.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Dict, Optional, Protocol

__all__ = [
    "LLM",
    "LLMError",
    "OllamaLLM",
    "OpenAICompatibleLLM",
    "HuggingFaceLLM",
    "EchoLLM",
    "build",
    "PROVIDERS",
    "describe_providers",
]


class LLMError(RuntimeError):
    """Backend failed. Always caught by the caller — an explanation that
    cannot be produced must degrade to the computed report, never to an
    error the operator has to work around."""


class LLM(Protocol):
    """One call, one string back.

    Deliberately minimal. No streaming, no tools, no function calling: the
    only thing a model is permitted to do in this tool is turn computed
    numbers into prose, and a richer interface would invite it to do more.
    """

    name: str

    def complete(self, system: str, prompt: str,
                 max_tokens: int = 1200, temperature: float = 0.2) -> str: ...


def _post(url: str, payload: dict, headers: Dict[str, str],
          timeout: float) -> dict:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:400]
        raise LLMError(f"{url} returned HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise LLMError(f"{url} unreachable: {error.reason}") from error
    except (TimeoutError, OSError) as error:
        raise LLMError(f"{url} failed: {error}") from error
    except json.JSONDecodeError as error:
        raise LLMError(f"{url} returned invalid JSON: {error}") from error


class OllamaLLM:
    """Local Ollama over its native /api/chat.

    `think: false` is sent because reasoning-style models otherwise prefix
    every answer with a visible thinking monologue, and there is no
    server-side default for it. The explanation path then has to strip prose
    it did not ask for, and sometimes strips the answer with it.
    """

    def __init__(self, model: str = "qwen-abl",
                 url: str = "http://127.0.0.1:11434",
                 timeout: float = 180.0):
        self.model = model
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.name = f"ollama/{model}"

    def complete(self, system: str, prompt: str,
                 max_tokens: int = 1200, temperature: float = 0.2) -> str:
        data = _post(
            f"{self.url}/api/chat",
            {
                "model": self.model,
                "stream": False,
                "think": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            },
            headers={},
            timeout=self.timeout,
        )
        message = (data.get("message") or {}).get("content")
        if not message:
            raise LLMError(f"ollama returned no content: {str(data)[:200]}")
        return message


class OpenAICompatibleLLM:
    """Any endpoint speaking the OpenAI chat-completions API.

    This is the extension point for new models. Ollama's own /v1, llama.cpp's
    server, vLLM, LM Studio, Together, Groq and OpenAI all speak it, so a new
    backend is usually a base URL and a key rather than new code.
    """

    def __init__(self, model: str, url: str = "https://api.openai.com/v1",
                 api_key: Optional[str] = None, timeout: float = 180.0,
                 label: str = "openai"):
        self.model = model
        self.url = url.rstrip("/")
        # A local server accepts any string; a hosted one needs a real key.
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or "local"
        self.timeout = timeout
        self.name = f"{label}/{model}"

    def complete(self, system: str, prompt: str,
                 max_tokens: int = 1200, temperature: float = 0.2) -> str:
        data = _post(
            f"{self.url}/chat/completions",
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
                # Honoured by Ollama's /v1 and ignored elsewhere; same
                # purpose as `think: false` above.
                "reasoning_effort": "none",
            },
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout,
        )
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"no choices returned: {str(data)[:200]}")
        content = (choices[0].get("message") or {}).get("content")
        if not content:
            raise LLMError(f"empty completion: {str(data)[:200]}")
        return content


class HuggingFaceLLM(OpenAICompatibleLLM):
    """Hugging Face Inference Providers, which speak chat-completions.

    A subclass rather than a configuration note because the base URL and the
    token environment variable differ, and getting either wrong produces a
    401 that reads like a bad key.

    THIS IS A HOSTED BACKEND. Whatever is in the prompt leaves the machine.
    Secrets are redacted before the prompt is built, but hostnames, SNIs and
    DNS names are the subject matter and cannot be — so choosing this for a
    client's capture is a disclosure decision, not a performance one.
    """

    def __init__(self, model: str = "Qwen/Qwen2.5-7B-Instruct",
                 url: str = "https://router.huggingface.co/v1",
                 api_key: Optional[str] = None, timeout: float = 180.0):
        token = (
            api_key
            or os.environ.get("HF_TOKEN")
            or os.environ.get("HUGGINGFACE_API_KEY")
        )
        if not token:
            raise LLMError(
                "huggingface needs a token: set HF_TOKEN (or pass --llm-key). "
                "https://huggingface.co/settings/tokens"
            )
        super().__init__(model=model, url=url, api_key=token,
                         timeout=timeout, label="hf")


class EchoLLM:
    """No network. Returns a valid, deliberately uninteresting answer.

    Exists so the explanation pipeline — prompt construction, parsing,
    citation verification, fallback — is testable without a model, a GPU or
    a network. The citation checks are the part worth testing, and they do
    not care who wrote the text.
    """

    def __init__(self, reply: Optional[str] = None):
        self.reply = reply
        self.name = "echo"
        self.calls: list = []

    def complete(self, system: str, prompt: str,
                 max_tokens: int = 1200, temperature: float = 0.2) -> str:
        self.calls.append((system, prompt))
        if self.reply is not None:
            return self.reply
        return json.dumps({
            "summary": "No model configured; this is a placeholder.",
            "reasoning": "The echo backend does not analyse anything.",
            "cited": [],
        })


#: name -> factory(model, url, api_key, timeout)
PROVIDERS = {
    "ollama": lambda model, url, key, timeout: OllamaLLM(
        model=model or "qwen-abl",
        url=url or "http://127.0.0.1:11434",
        timeout=timeout,
    ),
    "openai": lambda model, url, key, timeout: OpenAICompatibleLLM(
        model=model or "gpt-4o-mini",
        url=url or "https://api.openai.com/v1",
        api_key=key, timeout=timeout,
    ),
    "huggingface": lambda model, url, key, timeout: HuggingFaceLLM(
        model=model or "Qwen/Qwen2.5-7B-Instruct",
        url=url or "https://router.huggingface.co/v1",
        api_key=key, timeout=timeout,
    ),
    "echo": lambda model, url, key, timeout: EchoLLM(),
}

#: Backends that send the prompt off this machine. Named so the CLI can warn
#: once, loudly, rather than leaving the operator to infer it.
REMOTE_PROVIDERS = frozenset({"openai", "huggingface"})


def build(
    provider: str = "ollama",
    model: str = "",
    url: str = "",
    api_key: Optional[str] = None,
    timeout: float = 180.0,
) -> LLM:
    factory = PROVIDERS.get(provider)
    if factory is None:
        raise LLMError(
            f"unknown provider {provider!r}; available: "
            + ", ".join(sorted(PROVIDERS))
        )
    return factory(model, url, api_key, timeout)


def describe_providers() -> str:
    return (
        "ollama       local Ollama (default), e.g. --llm-model qwen-abl\n"
        "openai       any OpenAI-compatible endpoint: OpenAI, vLLM,\n"
        "             llama.cpp, LM Studio, Together, Groq. Needs\n"
        "             --llm-url and OPENAI_API_KEY unless local.\n"
        "huggingface  HF Inference Providers. Needs HF_TOKEN.\n"
        "echo         no network; used by the tests."
    )
