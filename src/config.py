"""Loads config/settings.yaml and resolves paths against the repository root."""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_PATH = REPO_ROOT / "config" / "settings.yaml"


def load_settings(path=None):
    with open(path or SETTINGS_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve(path):
    """Return an absolute Path; relative paths are taken from the repo root."""
    p = Path(path)
    return p if p.is_absolute() else REPO_ROOT / p
