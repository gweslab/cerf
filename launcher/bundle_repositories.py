from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from app_paths import install_root

MAIN_REPOSITORY_URL = "https://cerf-bundles.dz3n.net/cerf-bundles"
CONFIG_KEY = "bundle_repositories"
_MANIFEST_NAME = "manifest.json"
_ANALYTICS_NAME = "analytics.json"


@dataclass
class BundleRepository:
    url: str
    enabled: bool


def config_path() -> Path:
    return install_root() / "cerf.json"


def manifest_url_for(base_url: str) -> str:
    return base_url.rstrip("/") + "/" + _MANIFEST_NAME


def analytics_url_for(base_url: str) -> str:
    return base_url.rstrip("/") + "/" + _ANALYTICS_NAME


def default_repositories() -> List[BundleRepository]:
    return [BundleRepository(url=MAIN_REPOSITORY_URL, enabled=True)]


def _parse_repositories(raw) -> Optional[List[BundleRepository]]:
    """Reads the config list; a legacy "main" key on an entry is ignored."""
    if not isinstance(raw, list):
        return None
    repos: List[BundleRepository] = []
    seen: set = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        enabled = item.get("enabled")
        if not isinstance(url, str) or not url or not isinstance(enabled, bool):
            continue
        if url in seen:
            continue
        seen.add(url)
        repos.append(BundleRepository(url=url, enabled=enabled))
    return repos or None


def load_config(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8-sig")
        parsed = json.loads(text)
    except (OSError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def read_repositories() -> List[BundleRepository]:
    repos = _parse_repositories(load_config(config_path()).get(CONFIG_KEY))
    return repos if repos is not None else default_repositories()


def write_repositories(repos: List[BundleRepository]) -> None:
    path = config_path()
    obj = load_config(path)
    obj[CONFIG_KEY] = [{"url": r.url, "enabled": r.enabled} for r in repos]
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def strip_manifest_from_repos(value):
    if not isinstance(value, list):
        return value
    suffix = "/" + _MANIFEST_NAME
    out = []
    for e in value:
        if isinstance(e, dict) and isinstance(e.get("url"), str) \
                and e["url"].endswith(suffix):
            e = dict(e)
            e["url"] = e["url"][:-len(suffix)]
        out.append(e)
    return out


def merge_repositories(old_value, new_value):
    if not isinstance(old_value, list):
        return new_value
    merged = [e for e in old_value if isinstance(e, dict)]
    old_urls = {e.get("url") for e in merged if isinstance(e.get("url"), str)}
    if isinstance(new_value, list):
        for e in new_value:
            if isinstance(e, dict) and e.get("url") not in old_urls:
                merged.append(e)
    return merged
