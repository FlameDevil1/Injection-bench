# Tests for bench/config.py: valid configs load, bad ones fail with ConfigError.
from pathlib import Path

import pytest

from bench.config import ConfigError, load_config
from tests.conftest import ROOT, base_config, write_config


def test_shipped_configs_load():
    for name in ("config.yaml", "config.small.yaml", "config.mock.yaml"):
        cfg = load_config(ROOT / name)
        assert cfg.models and cfg.canary and cfg.marker


def test_defaults_are_inherited_and_overridable(tmp_path):
    data = base_config(tmp_path)
    data["models"].append({"name": "big", "provider": "ollama", "model": "x:8b", "trials": 1})
    cfg = load_config(write_config(tmp_path, data))
    small, big = cfg.models
    assert small.trials == 2 and big.trials == 1
    assert big.max_tokens == 50 and big.options["base_url"].startswith("http")


def test_disabled_models_are_filtered(tmp_path):
    data = base_config(tmp_path)
    data["models"].append({"name": "off", "provider": "mock", "model": "m", "enabled": False})
    cfg = load_config(write_config(tmp_path, data))
    assert [m.name for m in cfg.enabled_models()] == ["mock"]


def test_machine_name_comes_from_flag_then_environment(tmp_path, monkeypatch):
    path = write_config(tmp_path, base_config(tmp_path))
    assert load_config(path).machine == "testbox"
    assert load_config(path, "My PC!").machine == "my-pc-"
    assert load_config(path).machine_dir == tmp_path / "results" / "testbox"


def test_machine_can_change_only_non_scientific_settings(tmp_path):
    data = base_config(tmp_path)
    data["models"].append({"name": "big", "provider": "mock", "model": "big"})
    data["machines"] = {"TESTBOX": {"timeout_seconds": 99, "seconds_per_call_estimate": 2, "skip_models": ["big"]},
                        "other": {"timeout_seconds": 1}}
    cfg = load_config(write_config(tmp_path, data))
    assert cfg.models[0].timeout_seconds == 99 and cfg.models[0].seconds_per_call_estimate == 2
    assert [m.name for m in cfg.enabled_models()] == ["mock"]
    assert load_config(write_config(tmp_path, data), "other").models[0].timeout_seconds == 1


@pytest.mark.parametrize("key", ["temperature", "trials", "max_tokens", "base_seed", "defenses"])
def test_machine_cannot_change_the_experiment(tmp_path, key):
    data = base_config(tmp_path)
    data["machines"] = {"testbox": {key: 1}}
    with pytest.raises(ConfigError, match="vary per computer"):
        load_config(write_config(tmp_path, data))


def test_primary_machine_and_reports(tmp_path):
    data = base_config(tmp_path)
    data["run"]["primary_machine"] = "LAPTOP-1"
    data["reports"] = [{"name": "a", "title": "A", "defenses": ["D0", "D5"], "new_defenses": ["D5"]}]
    cfg = load_config(write_config(tmp_path, data))
    assert cfg.primary_machine == "laptop-1"
    assert cfg.reports[0].new_defenses == ["D5"]


def test_relative_paths_resolve_against_config_folder(tmp_path):
    data = base_config(tmp_path)
    data["paths"]["results_dir"] = "out"
    cfg = load_config(write_config(tmp_path, data))
    assert cfg.results_dir == tmp_path.resolve() / "out"


@pytest.mark.parametrize("mutate", [
    lambda d: d["defaults"].pop("trials"),
    lambda d: d["defaults"].update(trials="five"),
    lambda d: d["defaults"].update(temperature=5),
    lambda d: d["models"][0].update(provider="openai"),
    lambda d: d.update(models=[]),
    lambda d: d["models"].append(dict(d["models"][0])),  # duplicate name
    lambda d: d["defaults"].update(defenses=["D99"]),
    lambda d: d["defaults"].update(defenses=[]),
    lambda d: d["models"][0].update(provider="anthropic"),  # the proposals are local-only
    lambda d: d["app"].pop("lab_key"),
    lambda d: d.update(reports=[{"name": "a", "title": "A", "defenses": ["D99"]}]),
])
def test_invalid_configs_raise(tmp_path, mutate):
    data = base_config(tmp_path)
    mutate(data)
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


def test_malformed_yaml_and_missing_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("app: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad)
    with pytest.raises(ConfigError):
        load_config(Path(tmp_path / "nope.yaml"))
