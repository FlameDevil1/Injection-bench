# Reads config.yaml into plain dataclasses. Every tunable number (trials, temperature,
# timeouts, token limits), every path, and every model name lives in the YAML file;
# this module only loads it, fills per-model values from `defaults`, and fails early
# with a clear message if something is missing or has the wrong type.
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bench.defenses import DEFENSES

KNOWN_PROVIDERS = ("ollama", "mock", "anthropic")


class ConfigError(ValueError):
    """Raised when the config file is missing, malformed, or inconsistent."""


@dataclass
class ModelConfig:
    """Settings for one model entry; each entry gets its own results file."""

    name: str  # label used in result files and reports
    provider: str  # "ollama", "mock" or "anthropic"
    model: str  # model id passed to the provider
    enabled: bool
    trials: int
    temperature: float
    base_seed: int  # trial i uses seed base_seed + i
    max_tokens: int
    timeout_seconds: float
    seconds_per_call_estimate: float  # used for --dry-run and the first ETA only
    defenses: list[str]
    options: dict[str, Any] = field(default_factory=dict)  # provider-specific extras


@dataclass
class Config:
    """The whole experiment: app secrets, paths, run limits and models."""

    canary: str
    marker: str
    attacks_dir: Path
    benign_file: Path
    results_dir: Path
    cache_dir: Path | None
    max_calls: int | None
    max_consecutive_errors: int
    models: list[ModelConfig]

    def enabled_models(self) -> list[ModelConfig]:
        return [m for m in self.models if m.enabled]


def _get(d: dict, key: str, typ: type, where: str) -> Any:
    """Fetch d[key] and check its type (ints are accepted where floats are expected)."""
    if key not in d:
        raise ConfigError(f"{where}: missing required key '{key}'")
    val = d[key]
    if typ is float and isinstance(val, int) and not isinstance(val, bool):
        val = float(val)
    if not isinstance(val, typ) or (isinstance(val, bool) and typ is not bool):
        raise ConfigError(f"{where}: '{key}' must be of type {typ.__name__}, got {val!r}")
    return val


def _section(raw: dict, key: str) -> dict:
    val = raw.get(key)
    if not isinstance(val, dict):
        raise ConfigError(f"config: section '{key}' is missing or is not a mapping")
    return val


def _model(entry: Any, defaults: dict, index: int) -> ModelConfig:
    where = f"models[{index}]"
    if not isinstance(entry, dict):
        raise ConfigError(f"{where}: each model entry must be a mapping")
    merged = {**defaults, **entry}
    merged["options"] = {**defaults.get("options", {}), **entry.get("options", {})}
    provider = _get(merged, "provider", str, where)
    if provider not in KNOWN_PROVIDERS:
        raise ConfigError(f"{where}: unknown provider '{provider}' (use one of {KNOWN_PROVIDERS})")
    # The paid Anthropic API must be switched on explicitly, entry by entry.
    enabled = merged.get("enabled", provider != "anthropic")
    if not isinstance(enabled, bool):
        raise ConfigError(f"{where}: 'enabled' must be true or false")
    mc = ModelConfig(
        name=_get(merged, "name", str, where),
        provider=provider,
        model=_get(merged, "model", str, where),
        enabled=enabled,
        trials=_get(merged, "trials", int, where),
        temperature=_get(merged, "temperature", float, where),
        base_seed=_get(merged, "base_seed", int, where),
        max_tokens=_get(merged, "max_tokens", int, where),
        timeout_seconds=_get(merged, "timeout_seconds", float, where),
        seconds_per_call_estimate=_get(merged, "seconds_per_call_estimate", float, where),
        defenses=_get(merged, "defenses", list, where),
        options=merged["options"],
    )
    if mc.trials < 1 or mc.max_tokens < 1 or mc.timeout_seconds <= 0:
        raise ConfigError(f"{where}: trials, max_tokens and timeout_seconds must be positive")
    if not 0.0 <= mc.temperature <= 2.0:
        raise ConfigError(f"{where}: temperature must be between 0 and 2")
    unknown = [d for d in mc.defenses if d not in DEFENSES]
    if not mc.defenses or unknown:
        raise ConfigError(f"{where}: 'defenses' must be a non-empty list of {sorted(DEFENSES)}; unknown: {unknown}")
    if provider == "ollama" and not isinstance(mc.options.get("base_url"), str):
        raise ConfigError(f"{where}: ollama models need options.base_url")
    if provider == "anthropic" and not isinstance(mc.options.get("api_url"), str):
        raise ConfigError(f"{where}: anthropic models need options.api_url")
    return mc


def load_config(path: str | Path) -> Config:
    """Load and validate a config file. Relative paths are resolved against its folder."""
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a mapping at the top level")

    app, paths, defaults = _section(raw, "app"), _section(raw, "paths"), _section(raw, "defaults")
    run = raw.get("run") or {}
    base = path.resolve().parent

    def resolve(key: str) -> Path:
        return base / _get(paths, key, str, "paths")

    raw_models = raw.get("models")
    if not isinstance(raw_models, list) or not raw_models:
        raise ConfigError("config: 'models' must be a non-empty list")
    models = [_model(entry, defaults, i) for i, entry in enumerate(raw_models)]
    names = [m.name for m in models]
    if len(set(names)) != len(names):
        raise ConfigError(f"config: model names must be unique, got {names}")

    max_calls = run.get("max_calls")
    if max_calls is not None and (not isinstance(max_calls, int) or max_calls < 0):
        raise ConfigError("run: 'max_calls' must be null or a non-negative integer")
    cache = paths.get("cache_dir")
    return Config(
        canary=_get(app, "canary", str, "app"),
        marker=_get(app, "marker", str, "app"),
        attacks_dir=resolve("attacks_dir"),
        benign_file=resolve("benign_file"),
        results_dir=resolve("results_dir"),
        cache_dir=base / cache if isinstance(cache, str) else None,
        max_calls=max_calls,
        max_consecutive_errors=int(run.get("max_consecutive_errors", 10)),
        models=models,
    )
