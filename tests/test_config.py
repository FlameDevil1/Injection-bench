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


def test_anthropic_disabled_unless_explicit(tmp_path):
    data = base_config(tmp_path)
    data["defaults"]["options"]["api_url"] = "https://example.invalid"
    data["models"].append({"name": "claude", "provider": "anthropic", "model": "m"})
    cfg = load_config(write_config(tmp_path, data))
    assert [m.name for m in cfg.enabled_models()] == ["mock"]


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
