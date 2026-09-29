# Tests for bench/run.py: full mock runs, resume, limits, errors and interruption.
import json
import re

import pytest
import requests

from bench import provider as prov
from bench import run as runner
from bench.run import main
from tests.conftest import ROOT, base_config, write_config

N_ATTACKS, N_BENIGN = 36, 17
REQUIRED = {"case_id", "defense", "trial", "seed", "model", "response", "success", "elapsed_s"}


def rows(tmp_path, name="mock"):
    path = tmp_path / "results" / f"{name}.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass  # the deliberately half-written line in the resume test
    return out


def test_full_mock_run_writes_every_trial(tmp_path, config_path):
    assert main(["--config", str(config_path), "--no-report"]) == 0
    out = rows(tmp_path)
    assert len(out) == (N_ATTACKS + N_BENIGN) * 2 * 2  # cases x defenses x trials
    assert all(REQUIRED <= r.keys() for r in out)
    assert {r["seed"] for r in out} == {1000, 1001}
    assert all(r["error"] is None and isinstance(r["success"], bool) for r in out)
    # D4's input filter blocks some attacks without calling the model.
    assert any(r["defense"] == "D4" and str(r["blocked_by"]).startswith("input_regex") for r in out)


def test_resume_skips_done_trials_and_survives_half_written_line(tmp_path, config_path):
    main(["--config", str(config_path), "--no-report"])
    path = tmp_path / "results" / "mock.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    total = len(lines)
    path.write_text("\n".join(lines[:-10]) + "\n" + '{"case_id": "DO01", "defe', encoding="utf-8")
    main(["--config", str(config_path), "--no-report"])
    done = {(r["case_id"], r["defense"], r["trial"]) for r in rows(tmp_path)}
    assert len(done) == total and len(rows(tmp_path)) == total  # the 10 lost rows were redone, once
    before = len(rows(tmp_path))
    main(["--config", str(config_path), "--no-report"])
    assert len(rows(tmp_path)) == before  # nothing left to do


@pytest.mark.parametrize("cache", [True, False])
def test_dry_run_calls_nothing_and_estimate_matches_real_run(tmp_path, capsys, cache):
    data = base_config(tmp_path)
    if not cache:
        data["paths"]["cache_dir"] = None
    path = str(write_config(tmp_path, data))
    assert main(["--config", path, "--dry-run"]) == 0
    assert rows(tmp_path) == []
    planned = int(re.search(r"about (\d+) model calls", capsys.readouterr().out).group(1))
    main(["--config", path, "--no-report"])
    made = [r for r in rows(tmp_path) if not r["cached"] and not str(r["blocked_by"]).startswith("input")]
    assert planned == len(made) > 0


def test_max_calls_limit(tmp_path):
    data = base_config(tmp_path)
    data["paths"]["cache_dir"] = None
    main(["--config", str(write_config(tmp_path, data)), "--no-report", "--max-calls", "3"])
    called = [r for r in rows(tmp_path) if not str(r["blocked_by"]).startswith("input")]
    assert len(called) == 3


def test_cache_reuses_d0_responses_for_d1_and_d3(tmp_path):
    data = base_config(tmp_path)
    data["defaults"]["defenses"] = ["D0", "D1", "D3"]
    data["defaults"]["trials"] = 1
    main(["--config", str(write_config(tmp_path, data)), "--no-report"])
    out = rows(tmp_path)
    assert not any(r["cached"] for r in out if r["defense"] == "D0")
    assert all(r["cached"] for r in out if r["defense"] == "D3")


def test_provider_errors_are_recorded_and_retried(tmp_path):
    data = base_config(tmp_path)
    data["models"][0]["options"] = {"rules": [{"if_contains": "grandmother", "error": "simulated failure"}]}
    path = write_config(tmp_path, data)
    assert main(["--config", str(path), "--no-report"]) == 0
    failed = [r for r in rows(tmp_path) if r["error"]]
    assert failed and all(r["case_id"] == "RP02" and r["success"] is None for r in failed)
    n = len(rows(tmp_path))
    main(["--config", str(path), "--no-report"])
    assert len(rows(tmp_path)) == n + len(failed)  # only failed trials are retried


def test_gives_up_after_consecutive_errors(tmp_path):
    data = base_config(tmp_path)
    data["run"]["max_consecutive_errors"] = 3
    data["defaults"]["defenses"] = ["D0"]
    data["models"][0]["options"] = {"rules": [{"if_contains": "", "error": "model is down"}]}
    assert main(["--config", str(write_config(tmp_path, data)), "--no-report"]) == 0
    assert len(rows(tmp_path)) == 3


def test_unreachable_ollama_is_skipped_not_fatal(tmp_path, monkeypatch):
    def refuse(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(prov.requests, "get", refuse)
    monkeypatch.setattr(prov.requests, "post", refuse)
    data = base_config(tmp_path)
    data["models"].insert(0, {"name": "local", "provider": "ollama", "model": "llama3.2"})
    assert main(["--config", str(write_config(tmp_path, data)), "--no-report"]) == 0
    assert rows(tmp_path, "local") == [] and rows(tmp_path)  # mock still ran


def test_disabled_anthropic_never_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(prov, "AnthropicProvider", None)  # any attempt to build it would crash
    data = base_config(tmp_path)
    data["models"].append({"name": "claude", "provider": "anthropic", "model": "m",
                           "options": {"api_url": "https://example.invalid"}})
    assert main(["--config", str(write_config(tmp_path, data)), "--no-report"]) == 0
    assert rows(tmp_path, "claude") == []


def test_ctrl_c_keeps_partial_results_and_resume_finishes(tmp_path, config_path, monkeypatch, capsys):
    real = runner.run_job
    count = {"n": 0}

    def flaky(*args):
        count["n"] += 1
        if count["n"] > 5:
            raise KeyboardInterrupt
        return real(*args)

    monkeypatch.setattr(runner, "run_job", flaky)
    assert main(["--config", str(config_path), "--no-report"]) == 0
    assert len(rows(tmp_path)) == 5 and "Interrupted" in capsys.readouterr().out
    monkeypatch.setattr(runner, "run_job", real)
    main(["--config", str(config_path), "--no-report"])
    assert len(rows(tmp_path)) == (N_ATTACKS + N_BENIGN) * 2 * 2


def test_bad_attack_file_is_skipped(tmp_path):
    attacks = tmp_path / "attacks"
    attacks.mkdir()
    (attacks / "good.yaml").write_text((ROOT / "attacks" / "roleplay.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    (attacks / "bad.yaml").write_text("- id: [broken\n", encoding="utf-8")
    data = base_config(tmp_path)
    data["paths"]["attacks_dir"] = str(attacks)
    assert main(["--config", str(write_config(tmp_path, data)), "--no-report"]) == 0
    assert {r["category"] for r in rows(tmp_path)} == {"roleplay", "benign"}


def test_bad_config_returns_error_code(tmp_path, capsys):
    bad = tmp_path / "c.yaml"
    bad.write_text("app: {", encoding="utf-8")
    assert main(["--config", str(bad)]) == 2
    assert "Config error" in capsys.readouterr().err
