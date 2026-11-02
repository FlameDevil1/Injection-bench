# Records what produced a set of results, so runs on different computers can be trusted
# and compared: the hardware, Ollama version, exact model build, code version and a
# fingerprint of the attacks and prompts. Each computer keeps this in
# <results_dir>/<machine>/manifest.json. If something that affects the science changes
# partway through, a resumed run stops rather than quietly mixing two experiments.
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

from bench.app import CARRIER_HEAD, CARRIER_TAIL, DEFAULT_REQUEST, SYSTEM_TEMPLATE
from bench.config import Config, ModelConfig
from bench.defenses import HARDENING_TEMPLATE, INJECTION_PATTERNS, TEMPLATE_MARKERS
from bench.provider import Provider

# A resumed run must match the existing results on every one of these.
MUST_MATCH = ("model_digest", "server_version", "corpus_sha256", "protocol_sha256",
              "temperature", "base_seed", "max_tokens", "num_ctx")


def _sha256(data: object) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def corpus_hash(attacks: list, benign: list) -> str:
    """Fingerprint of the attacks and benign tasks (parsed, so line endings don't matter)."""
    return _sha256([sorted((asdict(a) for a in attacks), key=lambda a: a["id"]),
                    sorted((asdict(t) for t in benign), key=lambda t: t["id"])])


def protocol_hash(cfg: Config) -> str:
    """Fingerprint of the prompts and filters, so edits can't mix into existing results."""
    return _sha256([cfg.canary, cfg.marker, cfg.lab_key, SYSTEM_TEMPLATE, CARRIER_HEAD, CARRIER_TAIL, DEFAULT_REQUEST,
                    HARDENING_TEMPLATE, TEMPLATE_MARKERS.pattern, {k: p.pattern for k, p in INJECTION_PATTERNS.items()}])


def _command(*args: str) -> str:
    """Run a small read-only command and return its output, or '' if it isn't available."""
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
        return done.stdout.strip() if done.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def git_state(folder: Path) -> dict[str, object]:
    """The code version, and whether it has uncommitted changes."""
    commit = _command("git", "-C", str(folder), "rev-parse", "--short", "HEAD")
    changes = _command("git", "-C", str(folder), "status", "--porcelain", "--", "bench", "attacks", "data", "config.yaml")
    return {"commit": commit or "unknown", "uncommitted_changes": bool(changes)}


@lru_cache(maxsize=1)
def hardware_info() -> dict[str, object]:
    """OS, CPU, GPU and RAM. Anything that can't be detected is just left as 'unknown'."""
    info: dict[str, object] = {"os": platform.platform(), "python": sys.version.split()[0],
                               "cpu": platform.processor() or "unknown", "gpus": [], "ram_gb": "unknown"}
    script = ("[pscustomobject]@{cpu=(Get-CimInstance Win32_Processor).Name;"
              "ram=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory;"
              "gpus=@(Get-CimInstance Win32_VideoController | ForEach-Object Name)} | ConvertTo-Json")
    out = _command("powershell", "-NoProfile", "-NonInteractive", "-Command", script) if sys.platform == "win32" else ""
    try:
        found = json.loads(out)
        info.update(cpu=found["cpu"], ram_gb=round(found["ram"] / 1024**3, 1), gpus=found["gpus"])
    except (ValueError, KeyError, TypeError):
        pass
    nvidia = _command("nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader")
    if nvidia:
        info["nvidia"] = nvidia.splitlines()
    return info


def model_record(cfg: Config, mc: ModelConfig, provider: Provider, corpus_sha256: str) -> dict[str, object]:
    """What one model's results depend on, on this computer."""
    return {**provider.identity(), "corpus_sha256": corpus_sha256, "protocol_sha256": protocol_hash(cfg),
            "model_id": mc.model, "provider": mc.provider, "temperature": mc.temperature, "base_seed": mc.base_seed,
            "max_tokens": mc.max_tokens, "num_ctx": mc.options.get("num_ctx")}


def update_manifest(cfg: Config, mc: ModelConfig, provider: Provider, corpus_sha256: str) -> str | None:
    """Record this run in the manifest. Returns a problem message if it can't safely continue."""
    path = cfg.machine_dir / "manifest.json"
    manifest = {"machine": cfg.machine, "hardware": {}, "models": {}}
    if path.exists():
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return f"{path} is damaged; fix or delete it before resuming"
    record = model_record(cfg, mc, provider, corpus_sha256)
    old = manifest["models"].get(mc.name)
    if old:
        changed = [k for k in MUST_MATCH if old.get(k) != record.get(k)]
        if changed:
            return (f"{changed} changed since these results were started, so mixing them would be two experiments. "
                    f"Undo the change, or point results_dir at a new folder")
        record["git_commits"] = old.get("git_commits", [])
    commit = git_state(cfg.attacks_dir.parent)
    record["git_commits"] = [c for c in record.get("git_commits", []) if c != commit] + [commit]
    manifest["hardware"] = hardware_info()
    manifest["models"][mc.name] = record
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return None
