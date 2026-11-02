# Reads config.yaml into plain dataclasses. Every tunable number (trials, temperature,
# timeouts, token limits), every path, and every model name lives in the YAML file;
# this module only loads it, fills per-model values from `defaults`, and fails early
# with a clear message if something is missing or has the wrong type.
# The same config is shared by every computer. Its `machines` section can only change
# things that don't affect the science (timeouts, time estimates, which models to skip).
from __future__ import annotations

import os
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bench.defenses import DEFENSES

KNOWN_PROVIDERS = ("ollama", "mock")
MACHINE_KEYS = ("timeout_seconds", "seconds_per_call_estimate", "base_url", "skip_models")


class ConfigError(ValueError):
    """Raised when the config file is missing, malformed, or inconsistent."""


@dataclass
class ModelConfig:
    """Settings for one model entry; each entry gets its own results file."""

    name: str  # label used in result files and reports
    provider: str  # "ollama" or "mock"
    model: str  # model id passed to the provider
    enabled: bool
    trials: int
    temperature: float
    base_seed: int  # trial i uses seed base_seed + i
    max_tokens: int
    timeout_seconds: float
    seconds_per_call_estimate: float  # used for --dry-run only
    defenses: list[str]
    digest: str | None = None  # start of the exact model build every computer must use
    options: dict[str, Any] = field(default_factory=dict)  # provider-specific extras


@dataclass
class ReportSpec:
    """One report to generate: a title and the defenses it covers."""

    name: str
    title: str
    defenses: list[str]
    new_defenses: list[str] = field(default_factory=list)  # compared against the others in this report


@dataclass
class Config:
    """The whole experiment: app secrets, paths, run limits and models."""

    canary: str
    marker: str
    lab_key: str  # lab-only HMAC key for D5-D7; protects nothing real
    attacks_dir: Path
    benign_file: Path
    results_dir: Path
    cache_dir: Path | None
    max_calls: int | None
    max_consecutive_errors: int
    models: list[ModelConfig]
    machine: str = "unknown"  # this computer's label; its results go in results_dir/<machine>
    primary_machine: str | None = None  # the computer whose results the papers rely on
    corpus_sha256: str | None = None  # locks the attacks and benign tasks when set
    reports: list[ReportSpec] = field(default_factory=list)

    def enabled_models(self) -> list[ModelConfig]:
        return [m for m in self.models if m.enabled]

    @property
    def machine_dir(self) -> Path:
        return self.results_dir / self.machine

    @property
    def machine_cache_dir(self) -> Path | None:
        """Per computer, so a copied folder can't pass off another computer's replies as its own."""
        return self.cache_dir / self.machine if self.cache_dir else None


def machine_name(explicit: str | None = None) -> str:
    """This computer's label: --machine, else BENCH_MACHINE, else its hostname."""
    raw = explicit or os.environ.get("BENCH_MACHINE") or platform.node() or "unknown"
    return re.sub(r"[^a-z0-9._-]", "-", raw.lower())


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


def _check_defenses(names: Any, where: str) -> None:
    unknown = [d for d in names if d not in DEFENSES]
    if not names or unknown:
        raise ConfigError(f"{where}: 'defenses' must be a non-empty list of {sorted(DEFENSES)}; unknown: {unknown}")


def _model(entry: Any, defaults: dict, index: int) -> ModelConfig:
    where = f"models[{index}]"
    if not isinstance(entry, dict):
        raise ConfigError(f"{where}: each model entry must be a mapping")
    merged = {**defaults, **entry}
    merged["options"] = {**defaults.get("options", {}), **entry.get("options", {})}
    provider = _get(merged, "provider", str, where)
    if provider not in KNOWN_PROVIDERS:
        raise ConfigError(f"{where}: unknown provider '{provider}' (use one of {KNOWN_PROVIDERS})")
    enabled = merged.get("enabled", True)
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
        digest=merged.get("digest"),
        options=merged["options"],
    )
    if mc.trials < 1 or mc.max_tokens < 1 or mc.timeout_seconds <= 0:
        raise ConfigError(f"{where}: trials, max_tokens and timeout_seconds must be positive")
    if not 0.0 <= mc.temperature <= 2.0:
        raise ConfigError(f"{where}: temperature must be between 0 and 2")
    _check_defenses(mc.defenses, where)
    if provider == "ollama" and not isinstance(mc.options.get("base_url"), str):
        raise ConfigError(f"{where}: ollama models need options.base_url")
    return mc


def _apply_machine(models: list[ModelConfig], overrides: Any, machine: str) -> None:
    """Apply this computer's allowed settings. Anything else would change the experiment."""
    where = f"machines.{machine}"
    if not isinstance(overrides, dict):
        raise ConfigError(f"{where}: must be a mapping")
    unknown = sorted(set(overrides) - set(MACHINE_KEYS))
    if unknown:
        raise ConfigError(f"{where}: {unknown} can't vary per computer; allowed: {list(MACHINE_KEYS)}")
    for mc in models:
        if mc.name in overrides.get("skip_models", []):
            mc.enabled = False
        if "timeout_seconds" in overrides:
            mc.timeout_seconds = _get(overrides, "timeout_seconds", float, where)
        if "seconds_per_call_estimate" in overrides:
            mc.seconds_per_call_estimate = _get(overrides, "seconds_per_call_estimate", float, where)
        if "base_url" in overrides:
            mc.options["base_url"] = _get(overrides, "base_url", str, where)


def _reports(raw: Any) -> list[ReportSpec]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError("config: 'reports' must be a list")
    specs = []
    for i, item in enumerate(raw):
        where = f"reports[{i}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{where}: must be a mapping")
        spec = ReportSpec(_get(item, "name", str, where), _get(item, "title", str, where),
                          _get(item, "defenses", list, where), item.get("new_defenses") or [])
        _check_defenses(spec.defenses, where)
        specs.append(spec)
    return specs


def load_config(path: str | Path, machine: str | None = None) -> Config:
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

    machine = machine_name(machine)
    per_machine = {machine_name(name): value for name, value in (raw.get("machines") or {}).items()}
    _apply_machine(models, per_machine.get(machine) or {}, machine)

    max_calls = run.get("max_calls")
    if max_calls is not None and (not isinstance(max_calls, int) or max_calls < 0):
        raise ConfigError("run: 'max_calls' must be null or a non-negative integer")
    cache = paths.get("cache_dir")
    primary = run.get("primary_machine")
    return Config(
        canary=_get(app, "canary", str, "app"),
        marker=_get(app, "marker", str, "app"),
        lab_key=_get(app, "lab_key", str, "app"),
        attacks_dir=resolve("attacks_dir"),
        benign_file=resolve("benign_file"),
        results_dir=resolve("results_dir"),
        cache_dir=base / cache if isinstance(cache, str) else None,
        max_calls=max_calls,
        max_consecutive_errors=int(run.get("max_consecutive_errors", 10)),
        models=models,
        machine=machine,
        primary_machine=machine_name(primary) if primary else None,
        corpus_sha256=app.get("corpus_sha256"),
        reports=_reports(raw.get("reports")),
    )
