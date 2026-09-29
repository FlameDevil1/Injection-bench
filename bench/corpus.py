# Loads and validates the attack corpus (attacks/*.yaml). Each file is a list of cases
# with id, category, channel, payload and goal. A malformed file or case is reported
# and skipped, so one bad entry never stops a run.
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

CATEGORIES = ("direct_override", "roleplay", "indirect_document", "encoded", "delimiter_confusion")
CHANNELS = ("user_message", "document")
GOALS = ("leak_secret", "output_marker")
REQUIRED = ("id", "category", "channel", "payload", "goal")


@dataclass
class AttackCase:
    """One attack: where it enters the app (channel), what it says, and what it wants."""

    id: str
    category: str
    channel: str
    payload: str
    goal: str


def _check(item: object) -> str | None:
    """Return a description of what is wrong with one raw case, or None if it is valid."""
    if not isinstance(item, dict):
        return "case is not a mapping"
    missing = [k for k in REQUIRED if k not in item]
    if missing:
        return f"missing fields {missing}"
    if not all(isinstance(item[k], str) and item[k].strip() for k in REQUIRED):
        return "all fields must be non-empty strings"
    for key, allowed in (("category", CATEGORIES), ("channel", CHANNELS), ("goal", GOALS)):
        if item[key] not in allowed:
            return f"{key} '{item[key]}' is not one of {allowed}"
    return None


def load_attacks(attacks_dir: Path) -> tuple[list[AttackCase], list[str]]:
    """Load every *.yaml file in attacks_dir. Returns (valid cases, problems found)."""
    cases: list[AttackCase] = []
    problems: list[str] = []
    seen: set[str] = set()
    files = sorted(Path(attacks_dir).glob("*.yaml"))
    if not files:
        problems.append(f"no attack files found in {attacks_dir}")
    for path in files:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            problems.append(f"{path.name}: cannot load ({exc}); file skipped")
            continue
        if not isinstance(raw, list):
            problems.append(f"{path.name}: expected a list of cases; file skipped")
            continue
        for i, item in enumerate(raw):
            error = _check(item)
            if error is None and item["id"] in seen:
                error = f"duplicate id '{item['id']}'"
            if error:
                problems.append(f"{path.name} case #{i}: {error}; skipped")
                continue
            seen.add(item["id"])
            cases.append(AttackCase(*(item[k] for k in ("id", "category", "channel", "payload", "goal"))))
    return cases, problems
