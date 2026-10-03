"""A cerf.json key never changes its value type between releases: a changed
shape gets a NEW key, or cerf.exe keeps reading the old one. Every key already
present locally therefore stays as the user left it."""
from __future__ import annotations

import json
from pathlib import Path

from bundle_repositories import (CONFIG_KEY, merge_repositories,
                                 strip_manifest_from_repos)


def merge_preserving_old(old, new):
    if isinstance(old, dict) and isinstance(new, dict):
        merged = dict(old)
        for key, value in new.items():
            if key in merged:
                merged[key] = merge_preserving_old(merged[key], value)
            else:
                merged[key] = value
        return merged
    if isinstance(old, list) and isinstance(new, list):
        merged = list(old)
        for item in new:
            if item not in merged:
                merged.append(item)
        return merged
    return old


def _load(path: Path):
    # utf-8-sig: an installed cerf.json is hand-editable, and a Notepad save
    # leaves a BOM that a strict utf-8 decode chokes on.
    text = path.read_text(encoding="utf-8-sig")
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path}: top-level value is not an object")
    return parsed


def migrate_cerf_json(new_path: Path, installed_path: Path) -> None:
    new = _load(new_path)
    if not installed_path.is_file():
        merged = new
    else:
        old = _load(installed_path)
        merged = merge_preserving_old(old, new)
        merged[CONFIG_KEY] = merge_repositories(
            strip_manifest_from_repos(old.get(CONFIG_KEY)),
            new.get(CONFIG_KEY))
    installed_path.write_text(json.dumps(merged, indent=2) + "\n",
                              encoding="utf-8")
