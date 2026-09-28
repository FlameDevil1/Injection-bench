# Shared test helpers: a tiny valid config written into a temp folder.
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def base_config(tmp_path: Path) -> dict:
    """A minimal config dict that uses the real attack corpus and benign set with a mock model."""
    return {
        "app": {"canary": "CANARY-7f3a91", "marker": "PWNED-4471"},
        "paths": {
            "attacks_dir": str(ROOT / "attacks"),
            "benign_file": str(ROOT / "data" / "benign_tasks.yaml"),
            "results_dir": str(tmp_path / "results"),
            "cache_dir": str(tmp_path / "cache"),
        },
        "run": {"max_calls": None, "max_consecutive_errors": 10},
        "defaults": {
            "trials": 2, "temperature": 0.7, "base_seed": 1000, "max_tokens": 50,
            "timeout_seconds": 5, "seconds_per_call_estimate": 0.01, "defenses": ["D0", "D4"],
            "options": {"base_url": "http://localhost:11434"},
        },
        "models": [{"name": "mock", "provider": "mock", "model": "mock"}],
    }


def write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    return write_config(tmp_path, base_config(tmp_path))
