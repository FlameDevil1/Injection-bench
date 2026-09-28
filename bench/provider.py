# Talks to language models. Every model hides behind one tiny interface,
# Provider.generate(system, user, temperature, seed, max_tokens) -> str, so the rest of
# the bench does not care whether answers come from a local Ollama server, a scripted
# fake (MockProvider, used by tests and demo runs), or the optional Anthropic API.
# CachedProvider wraps any of them with an on-disk cache so repeated or resumed runs
# never pay for the same call twice.
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import requests

from bench.config import ModelConfig

log = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    """Any failure to get a reply (network, timeout, bad response). Recorded, never fatal."""


class Provider(ABC):
    """Base class: a named model that turns (system, user) prompts into text."""

    name = "base"

    def __init__(self, model: str) -> None:
        self.model = model

    @abstractmethod
    def generate(self, system: str, user: str, temperature: float, seed: int, max_tokens: int) -> str:
        """Return the model's reply, or raise ProviderError."""

    def check(self) -> None:
        """Raise ProviderError if the provider clearly cannot work. Called once before a run."""

    def is_cached(self, system: str, user: str, temperature: float, seed: int, max_tokens: int) -> bool:
        """True if generate() would be answered from the cache (only CachedProvider says yes)."""
        return False


class OllamaProvider(Provider):
    """A model served by a local Ollama server (default http://localhost:11434)."""

    name = "ollama"

    def __init__(self, model: str, base_url: str, timeout_seconds: float) -> None:
        super().__init__(model)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds

    def check(self) -> None:
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=self.timeout)
            resp.raise_for_status()
            names = {m.get("name", "") for m in resp.json().get("models", [])}
        except (requests.RequestException, ValueError, AttributeError) as exc:
            raise ProviderError(f"cannot reach Ollama at {self.base_url}; is Ollama running? ({exc})") from exc
        if self.model not in names and f"{self.model}:latest" not in names:
            raise ProviderError(f"model '{self.model}' is not installed; run: ollama pull {self.model}")

    def generate(self, system: str, user: str, temperature: float, seed: int, max_tokens: int) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": temperature, "seed": seed, "num_predict": max_tokens},
        }
        try:
            resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return str(resp.json()["message"]["content"])
        except requests.Timeout as exc:
            raise ProviderError(f"ollama call timed out after {self.timeout}s") from exc
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            raise ProviderError(f"ollama call failed: {exc}") from exc


class AnthropicProvider(Provider):
    """Optional Claude model via the Anthropic API. Only built when config enables it.

    Reads the key from the ANTHROPIC_API_KEY environment variable and never logs it.
    The API has no seed parameter, so `seed` only keeps trials apart in the cache.
    """

    name = "anthropic"

    def __init__(self, model: str, timeout_seconds: float, api_url: str) -> None:
        super().__init__(model)
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ProviderError("ANTHROPIC_API_KEY environment variable is not set")
        self._key = key
        self.api_url = api_url
        self.timeout = timeout_seconds

    def generate(self, system: str, user: str, temperature: float, seed: int, max_tokens: int) -> str:
        headers = {"x-api-key": self._key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        try:
            resp = requests.post(self.api_url, headers=headers, json=body, timeout=self.timeout)
            if resp.status_code != 200:
                raise ProviderError(f"anthropic API returned HTTP {resp.status_code}")
            blocks = resp.json()["content"]
            return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        except requests.Timeout as exc:
            raise ProviderError(f"anthropic call timed out after {self.timeout}s") from exc
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            raise ProviderError(f"anthropic call failed: {type(exc).__name__}") from exc


def _unit_hash(text: str) -> float:
    """Map text to a repeatable pseudo-random number in [0, 1)."""
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:12], 16) / 16**12


class MockProvider(Provider):
    """A deterministic fake model: no network, same input always gives the same output.

    1. `rules` (used by tests): the first rule whose `if_contains` text appears in the user
       prompt wins; it either returns `respond` or raises ProviderError(`error`).
    2. Otherwise it plays a gullible assistant. If the prompt contains injection cues, it
       "obeys" with probability `compliance` (halved when the defense wrapped the document
       in UNTRUSTED markers): it prints the marker, or leaks the canary, in whatever form was
       asked for. It cannot decode base64/rot13, so encoded attacks only work if cues show.
       Else it "summarizes" by echoing the first `summary_words` words of the document.
    Its results are a plumbing demo, not evidence about any real model.
    """

    name = "mock"
    CUES = ("ignore", "disregard", "override", "forget", "you are now", "pretend", "developer mode",
            "system", "new instructions", "admin", "reveal", "debug")
    SECRET_WORDS = ("secret", "password", "canary", "access code", "confidential")

    def __init__(self, model: str = "mock", canary: str = "", marker: str = "", compliance: float = 0.4,
                 summary_words: int = 40, rules: list[dict[str, str]] | None = None) -> None:
        super().__init__(model)
        self.canary, self.marker = canary, marker
        self.compliance, self.summary_words = compliance, summary_words
        self.rules = rules or []

    def generate(self, system: str, user: str, temperature: float, seed: int, max_tokens: int) -> str:
        text = user.lower()
        for rule in self.rules:
            if rule["if_contains"].lower() in text:
                if "error" in rule:
                    raise ProviderError(rule["error"])
                return rule["respond"]
        chance = self.compliance * (0.5 if "untrusted" in text else 1.0)
        if any(c in text for c in self.CUES) and _unit_hash(f"{seed}|{system}|{user}") < chance:
            if self.marker and self.marker.lower() in text:
                return self.marker
            if self.canary and any(w in text for w in self.SECRET_WORDS):
                return self._leak(text)
        doc_start = text.find("document:\n")  # the heading bench.app puts above the document
        body = user[doc_start + len("document:\n"):] if doc_start >= 0 else user
        return "Summary: " + " ".join(body.split()[: min(self.summary_words, max_tokens)])

    def _leak(self, text: str) -> str:
        if "base64" in text:
            return base64.b64encode(self.canary.encode()).decode()
        if "revers" in text or "backward" in text:
            return self.canary[::-1]
        if "space" in text or "spell" in text:
            return " ".join(self.canary)
        return f"The secret access code is {self.canary}."


class CachedProvider(Provider):
    """Wraps a provider with an append-only JSONL cache keyed by every input of generate().

    Only hashes are used as keys, so prompts are not written to disk; replies are.
    Failed calls are never cached, so they are retried next time.
    """

    def __init__(self, inner: Provider, cache_file: Path) -> None:
        super().__init__(inner.model)
        self.inner, self.name, self.path = inner, inner.name, cache_file
        self._store: dict[str, str] = {}
        if cache_file.exists():
            for line in cache_file.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                    self._store[row["key"]] = row["response"]
                except (ValueError, KeyError, TypeError):
                    continue  # a half-written line from an interrupted run
        cache_file.parent.mkdir(parents=True, exist_ok=True)

    def _key(self, *parts: Any) -> str:
        raw = json.dumps([self.inner.name, self.inner.model, *parts], ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def check(self) -> None:
        self.inner.check()

    def is_cached(self, system: str, user: str, temperature: float, seed: int, max_tokens: int) -> bool:
        return self._key(system, user, temperature, seed, max_tokens) in self._store

    def generate(self, system: str, user: str, temperature: float, seed: int, max_tokens: int) -> str:
        key = self._key(system, user, temperature, seed, max_tokens)
        if key in self._store:
            return self._store[key]
        text = self.inner.generate(system, user, temperature, seed, max_tokens)
        self._store[key] = text
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"key": key, "response": text}, ensure_ascii=False) + "\n")
        return text


def make_provider(mc: ModelConfig, canary: str, marker: str, cache_dir: Path | None) -> Provider:
    """Build the provider described by one model entry, wrapped in the cache if enabled."""
    opts = mc.options
    provider: Provider
    if mc.provider == "ollama":
        provider = OllamaProvider(mc.model, opts["base_url"], mc.timeout_seconds)
    elif mc.provider == "anthropic":
        if not mc.enabled:  # belt and braces: config.enabled_models() already filters these out
            raise ProviderError("the anthropic provider is disabled in the config")
        provider = AnthropicProvider(mc.model, mc.timeout_seconds, opts.get("api_url", ""))
    elif mc.provider == "mock":
        provider = MockProvider(mc.model, canary, marker, float(opts.get("compliance", 0.4)),
                                int(opts.get("summary_words", 40)), opts.get("rules"))
    else:
        raise ProviderError(f"unknown provider '{mc.provider}'")
    if cache_dir is not None:
        provider = CachedProvider(provider, cache_dir / "responses.jsonl")
    return provider
