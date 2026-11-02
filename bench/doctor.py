# Checks that this computer is ready to run the experiment, before you spend any time on
# it: code version, corpus lock, Ollama, exact model build, and whether the model really
# runs on the GPU, with a measured speed and a time estimate. Changes nothing in results.
#   python -m bench.doctor --config config.yaml [--machine NAME]
from __future__ import annotations

import argparse
import sys
from datetime import timedelta

import requests

from bench.app import build_prompt, load_benign_tasks, make_input
from bench.config import ConfigError, ModelConfig, load_config
from bench.corpus import load_attacks
from bench.provenance import corpus_hash, git_state, hardware_info
from bench.provider import ModelMissing, ProviderError, make_provider
from bench.run import build_jobs, planned_calls
from bench.scoring import Secrets


def speed_test(mc: ModelConfig, canary: str) -> str:
    """One real model call: how fast is it, and how much of the model is on the GPU?"""
    base = mc.options["base_url"].rstrip("/")
    system, user = build_prompt(make_input("Summarize this in two sentences.", "Lunch is on Friday at noon.", canary))
    options = {"temperature": mc.temperature, "seed": mc.base_seed, "num_predict": mc.max_tokens}
    if mc.options.get("num_ctx"):
        options["num_ctx"] = mc.options["num_ctx"]
    reply = requests.post(f"{base}/api/chat", timeout=mc.timeout_seconds, json={
        "model": mc.model, "stream": False, "options": options,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}).json()
    speed = reply.get("eval_count", 0) / max(reply.get("eval_duration", 1) / 1e9, 1e-9)
    loaded = [m for m in requests.get(f"{base}/api/ps", timeout=10).json().get("models", [])
              if m.get("name", "").split(":")[0] == mc.model.split(":")[0]]
    on_gpu = loaded[0].get("size_vram", 0) / max(loaded[0].get("size", 1), 1) if loaded else 0.0
    note = "" if on_gpu > 0.99 else ("  << running partly on the CPU, so expect it to be slower" if on_gpu else "  << running on the CPU only")
    return f"{speed:.0f} tokens/s, {on_gpu:.0%} on the GPU{note}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check this computer is ready to run the bench.")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--machine", default=None, help="this computer's label (default: BENCH_MACHINE or hostname)")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config, args.machine)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    problems: list[str] = []
    hardware = hardware_info()
    print(f"Computer: {cfg.machine}" + ("  (the primary computer)" if cfg.machine == cfg.primary_machine else ""))
    print(f"  {hardware['cpu']} | {hardware['ram_gb']} GB RAM | GPUs: {', '.join(hardware['gpus']) or 'unknown'}")
    print(f"  Python {hardware['python']} on {hardware['os']}")
    if hardware.get("nvidia"):
        print(f"  NVIDIA: {'; '.join(hardware['nvidia'])}")

    git = git_state(cfg.attacks_dir.parent)
    print(f"Code version: {git['commit']}" + ("  << has uncommitted changes" if git["uncommitted_changes"] else ""))
    if git["uncommitted_changes"]:
        problems.append("commit or discard local changes so every computer runs the same code")

    attacks, attack_problems = load_attacks(cfg.attacks_dir)
    benign, benign_problems = load_benign_tasks(cfg.benign_file)
    problems += attack_problems + benign_problems
    fingerprint = corpus_hash(attacks, benign)
    print(f"Corpus: {len(attacks)} attacks, {len(benign)} benign tasks, fingerprint {fingerprint[:12]}")
    if cfg.corpus_sha256 and fingerprint != cfg.corpus_sha256:
        problems.append(f"the corpus doesn't match the locked fingerprint {cfg.corpus_sha256[:12]}")

    secrets = Secrets(cfg.canary, cfg.marker, cfg.lab_key)
    ready = 0
    for mc in cfg.enabled_models():
        try:
            provider = make_provider(mc, cfg.canary, cfg.marker, cfg.machine_cache_dir)
            provider.check()
        except ModelMissing as exc:
            print(f"Model {mc.name}: {exc}. It will be skipped.")
            continue
        except ProviderError as exc:
            print(f"Model {mc.name}: {exc}")
            problems.append(f"{mc.name}: {exc}")
            continue
        ready += 1
        identity = provider.identity()
        print(f"Model {mc.name}: build {identity['model_digest'][:12] or 'n/a'}, Ollama {identity['server_version'] or 'n/a'}")
        calls = planned_calls(build_jobs(mc, attacks, benign, cfg.canary), provider, mc, cfg.cache_dir is not None, secrets)
        if mc.provider == "ollama":
            try:
                print(f"  speed test: {speed_test(mc, cfg.canary)}")
            except (requests.RequestException, ValueError) as exc:
                problems.append(f"{mc.name}: speed test failed ({exc})")
        print(f"  {calls} model calls for the full grid, roughly {timedelta(seconds=round(calls * mc.seconds_per_call_estimate))} "
              f"at the config's {mc.seconds_per_call_estimate:g}s per call")

    if not ready:
        problems.append("no model is ready to run")
    if problems:
        print("\nNot ready yet:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nReady to run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
