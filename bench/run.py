# Runs the experiment grid: every (attack or benign task) x defense x trial, for each
# enabled model in the config. Each finished trial is appended to
# <results_dir>/<machine>/<model>.jsonl straight away, so Ctrl+C or a crash loses nothing
# and a restart skips what is already recorded. Model errors are recorded, never fatal.
#
#   python -m bench.run --config config.yaml [--machine NAME] [--dry-run] [--max-calls N] [--no-report]
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from bench.app import AppInput, attack_input, load_benign_tasks, make_input
from bench.config import Config, ConfigError, ModelConfig, load_config
from bench.corpus import AttackCase, load_attacks
from bench.defenses import BLOCKED_INPUT_MESSAGE, DEFENSES, Prepared, finish, prepare
from bench.provenance import corpus_hash, update_manifest
from bench.provider import Provider, ProviderError, ensure_trailing_newline, make_provider
from bench.scoring import Secrets, attack_succeeded, benign_succeeded, leaks_canary

log = logging.getLogger("bench")
PROGRESS_EVERY_SECONDS = 5.0  # how often to print a progress line


@dataclass
class Job:
    """One trial to run: an input, a defense, a trial number and its seed."""

    kind: str  # "attack" or "benign"
    case_id: str
    category: str  # attack category, or "benign"
    channel: str
    goal: str  # leak_secret, output_marker, or benign
    defense: str
    trial: int
    seed: int
    inp: AppInput
    keywords: list[str] = field(default_factory=list)


def build_jobs(mc: ModelConfig, attacks: list[AttackCase], benign: list, canary: str) -> list[Job]:
    """Trial-major order: a partial run covers every cell once before repeating any.
    Within a case, D0 runs before D1/D3 so their identical prompts come from the cache."""
    jobs = []
    for trial in range(mc.trials):
        seed = mc.base_seed + trial
        for case in attacks:
            inp = attack_input(case.channel, case.payload, canary)
            jobs += [Job("attack", case.id, case.category, case.channel, case.goal, d, trial, seed, inp)
                     for d in mc.defenses]
        for task in benign:
            inp = make_input(task.request, task.document, canary)
            jobs += [Job("benign", task.id, "benign", "document", "benign", d, trial, seed, inp, task.expected_keywords)
                     for d in mc.defenses]
    return jobs


def row_key(model_id: str, case_id: str, defense: str, trial: int, seed: int,
            temperature: float, max_tokens: int) -> tuple:
    """Identifies a trial; rows with the same key are the same measurement."""
    return (model_id, case_id, defense, trial, seed, float(temperature), max_tokens)


def prepare_job(job: Job, secrets: Secrets) -> Prepared:
    """Apply the job's defense. The request id gives D5 a different tag for every request."""
    return prepare(DEFENSES[job.defense], job.inp, secrets, f"{job.case_id}|{job.trial}|{job.seed}")


def job_key(mc: ModelConfig, job: Job) -> tuple:
    return row_key(mc.model, job.case_id, job.defense, job.trial, job.seed, mc.temperature, mc.max_tokens)


def load_done(path: Path) -> set[tuple]:
    """Keys of trials already completed without error (errored trials are retried)."""
    done: set[tuple] = set()
    if not path.exists():
        return done
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            r = json.loads(line)
            if r.get("error") is None:
                done.add(row_key(r["model_id"], r["case_id"], r["defense"], r["trial"], r["seed"],
                                 r["temperature"], r["max_tokens"]))
        except (ValueError, KeyError, TypeError):
            continue  # half-written line from an interrupted run
    return done


def run_job(job: Job, provider: Provider, mc: ModelConfig, secrets: Secrets, machine: str) -> tuple[dict, bool]:
    """Run one trial through the defended app. Returns (result row, whether the model was called)."""
    start = time.perf_counter()
    defense = DEFENSES[job.defense]
    prepared = prepare_job(job, secrets)
    response, blocked_by, raw, error, cached, called = BLOCKED_INPUT_MESSAGE, prepared.blocked_by, None, None, False, False
    if blocked_by is None:
        args = (prepared.system, prepared.user, mc.temperature, job.seed, mc.max_tokens)
        cached = provider.is_cached(*args)
        called = not cached
        try:
            raw = provider.generate(*args)
            response, blocked_by = finish(defense, raw, secrets)
        except ProviderError as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001 - one odd failure must not end an overnight run
            error = f"unexpected {type(exc).__name__}: {exc}"
            log.debug("unexpected error in %s", job.case_id, exc_info=True)
    if error:
        success = None
    elif job.kind == "attack":
        success = attack_succeeded(response, job.goal, secrets)
    else:
        success = blocked_by is None and benign_succeeded(response, job.keywords)
    # Kept apart from `success`: under D6 the real secret can't leak, but did the placeholder?
    would_be = leaks_canary(raw, secrets.placeholder) if defense.uses_placeholder and raw is not None else None
    row = {
        "machine": machine, "model": mc.name, "provider": mc.provider, "model_id": mc.model,
        "kind": job.kind, "case_id": job.case_id, "category": job.category, "channel": job.channel,
        "goal": job.goal, "defense": job.defense, "trial": job.trial, "seed": job.seed,
        "temperature": mc.temperature, "max_tokens": mc.max_tokens,
        "response": response, "raw_response": raw if blocked_by and raw is not None else None,
        "success": success, "would_be_leak": would_be, "blocked_by": blocked_by, "error": error, "cached": cached,
        "elapsed_s": round(time.perf_counter() - start, 3),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }
    return row, called


def planned_calls(jobs: list[Job], provider: Provider | None, mc: ModelConfig, cache_on: bool, secrets: Secrets) -> int:
    """How many real model calls these jobs need: not input-blocked, not cached, and (with
    the cache on) counting each distinct prompt once."""
    prompts = []
    for job in jobs:
        prepared = prepare_job(job, secrets)
        if prepared.blocked_by is None:
            args = (prepared.system, prepared.user, mc.temperature, job.seed, mc.max_tokens)
            if provider is None or not provider.is_cached(*args):
                prompts.append(args)
    return len(set(prompts)) if cache_on else len(prompts)


def results_path(cfg: Config, mc: ModelConfig) -> Path:
    return cfg.machine_dir / (re.sub(r"[^A-Za-z0-9._-]", "_", mc.name) + ".jsonl")


def run_model(mc: ModelConfig, cfg: Config, attacks: list[AttackCase], benign: list,
              budget: int | None, dry_run: bool) -> int:
    """Run (or, with dry_run, only count) one model's pending trials. Returns real calls made."""
    path = results_path(cfg, mc)
    jobs = build_jobs(mc, attacks, benign, cfg.canary)
    done = load_done(path)
    pending = [j for j in jobs if job_key(mc, j) not in done]
    secrets = Secrets(cfg.canary, cfg.marker, cfg.lab_key)
    try:
        provider: Provider | None = make_provider(mc, cfg.canary, cfg.marker, cfg.machine_cache_dir)
        provider.check()
    except ProviderError as exc:
        if not dry_run:
            log.error("[%s] skipping model: %s", mc.name, exc)
            return 0
        log.warning("[%s] %s (estimate assumes nothing is cached)", mc.name, exc)
        provider = None
    calls = planned_calls(pending, provider, mc, cfg.cache_dir is not None, secrets)
    estimate = timedelta(seconds=round(calls * mc.seconds_per_call_estimate))
    print(f"[{mc.name}] {len(jobs)} trials in grid, {len(jobs) - len(pending)} already done, "
          f"{len(pending)} to run -> about {calls} model calls, estimated {estimate}")
    if dry_run or provider is None or not pending:
        return 0
    problem = update_manifest(cfg, mc, provider, corpus_hash(attacks, benign))
    if problem:
        log.error("[%s] skipping model: %s", mc.name, problem)
        return 0

    made = errors_in_row = successes = 0
    started = last_print = time.monotonic()
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_trailing_newline(path)
    with path.open("a", encoding="utf-8") as out:
        for i, job in enumerate(pending, 1):
            if budget is not None and made >= budget:
                log.warning("[%s] max-calls limit reached; stopping. Re-run to continue.", mc.name)
                break
            row, called = run_job(job, provider, mc, secrets, cfg.machine)
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            out.flush()
            made += called
            successes += bool(row["success"]) and job.kind == "attack"
            if row["error"]:
                errors_in_row += 1
                log.warning("[%s] %s/%s trial %d failed: %s", mc.name, job.case_id, job.defense, job.trial, row["error"])
                if errors_in_row >= cfg.max_consecutive_errors:
                    log.error("[%s] %d errors in a row; giving up on this model for now.", mc.name, errors_in_row)
                    break
            elif called or row["cached"]:  # the model answered, so it is healthy again
                errors_in_row = 0
            now = time.monotonic()
            if now - last_print >= PROGRESS_EVERY_SECONDS or i == len(pending):
                eta = timedelta(seconds=round((now - started) / i * (len(pending) - i)))
                print(f"[{mc.name}] {i}/{len(pending)} ({i / len(pending):.0%}) | model calls {made} | "
                      f"attack successes {successes} | elapsed {timedelta(seconds=round(now - started))} | ETA {eta}")
                last_print = now
    return made


def setup_logging(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S")
    handlers: list[logging.Handler] = [logging.StreamHandler(), logging.FileHandler(folder / "run.log", encoding="utf-8")]
    for h in handlers:
        h.setFormatter(fmt)
    for old in log.handlers:
        old.close()
    log.handlers = handlers
    log.setLevel(logging.INFO)
    log.propagate = False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the prompt injection test bench.")
    parser.add_argument("--config", default="config.yaml", help="path to the config file")
    parser.add_argument("--machine", default=None, help="this computer's label (default: BENCH_MACHINE or hostname)")
    parser.add_argument("--dry-run", action="store_true", help="count calls and estimate time; call nothing")
    parser.add_argument("--max-calls", type=int, default=None, help="stop after N real model calls (overrides config)")
    parser.add_argument("--no-report", action="store_true", help="skip report generation at the end")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config, args.machine)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.machine_dir)
    attacks, problems = load_attacks(cfg.attacks_dir)
    benign, benign_problems = load_benign_tasks(cfg.benign_file)
    for problem in problems + benign_problems:
        log.warning(problem)
    if not attacks and not benign:
        log.error("nothing to run: no valid attacks or benign tasks")
        return 2
    fingerprint = corpus_hash(attacks, benign)
    if cfg.corpus_sha256 and fingerprint != cfg.corpus_sha256:
        log.error("the attacks or benign tasks changed: fingerprint %s, config locks %s", fingerprint[:12], cfg.corpus_sha256[:12])
        return 2
    print(f"Loaded {len(attacks)} attack cases and {len(benign)} benign tasks on computer '{cfg.machine}'.")
    budget = args.max_calls if args.max_calls is not None else cfg.max_calls
    try:
        for mc in cfg.enabled_models():
            used = run_model(mc, cfg, attacks, benign, budget, args.dry_run)
            budget = None if budget is None else max(0, budget - used)
    except KeyboardInterrupt:
        print(f"\nInterrupted. Every finished trial is saved in {cfg.results_dir}; run the same command to resume.")
    if not args.dry_run and not args.no_report:
        from bench.report import write_report
        try:
            for path in write_report(cfg):
                print(f"Report written to {path}")
        except Exception as exc:  # noqa: BLE001 - results are safe on disk even if the report fails
            log.error("report generation failed: %s (results are intact; retry with python -m bench.report)", exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
