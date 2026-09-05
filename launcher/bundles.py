from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bundle_repositories import (BundleRepository, analytics_url_for,
                                 manifest_url_for)

SUPPORTED_REMOTE_MANIFEST_VERSION = 2

USER_AGENT = "CERF launcher"
SAFE_BUNDLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\- ]*$")
_WINDOWS_RESERVED_NAMES = (
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)
DEFAULT_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 120
DOWNLOAD_CHUNK = 1024 * 1024
PARALLEL_WORKERS = 4

# Compressed-download size above which the GUI offers a manual browser download
# instead of streaming through the launcher (a >=2 GB ROM over a flaky link is
# unreliable to pull in-process). GUI-only; the CLI always streams.
LARGE_DOWNLOAD_THRESHOLD = 300 * 1024 * 1024

# Human-readable labels for additional-package categories. Categories without
# a mapping are displayed under their raw manifest key.
PACKAGE_CATEGORY_LABELS = {
    "pdbs": "PDBs",
    "compact_flash_cards": "Compact Flash Cards",
    "sd_cards": "SD Cards",
    "usb_disks": "USB Disks",
}


def package_category_label(category: str) -> str:
    return PACKAGE_CATEGORY_LABELS.get(category, category)


class BundleError(RuntimeError):
    pass


class ManifestVersionError(BundleError):
    """Remote manifest schema version this CERF build cannot read."""

    def __init__(self, remote_version: int, supported_version: int):
        self.remote_version = remote_version
        self.supported_version = supported_version
        self.remote_is_newer = remote_version > supported_version
        if self.remote_is_newer:
            msg = (
                f"remote manifest version {remote_version} is newer than this "
                f"CERF build supports (version {supported_version}); download a "
                f"newer CERF build from https://cerf.cx/download/"
            )
        else:
            msg = (
                f"remote manifest version {remote_version} is older than this "
                f"CERF build expects (version {supported_version})"
            )
        super().__init__(msg)


@dataclass(frozen=True)
class RemotePackage:
    """One downloadable additional package of a bundle (PDBs, CF card
    images, ...). `key` is the artifact name the package produces in the
    device root: a single file when `is_directory` is False, a directory
    whose contents come from the archive root when True."""

    category: str
    key: str
    is_directory: bool
    name: str
    archive_path: str
    manifest_url: str
    archive_sha256: Optional[str] = None
    archive_size: Optional[int] = None
    unpacked_size: Optional[int] = None

    @property
    def archive_url(self) -> str:
        base = urllib.parse.urljoin(self.manifest_url, self.archive_path)
        if self.archive_sha256:
            return _append_query(base, "v", self.archive_sha256)
        return base


@dataclass(frozen=True)
class RemoteBundle:
    name: str
    repo_url: str
    updated_at: str
    archive_path: str
    manifest_url: str
    archive_sha256: Optional[str] = None
    archive_size: Optional[int] = None
    unpacked_size: Optional[int] = None
    cerf_json: Optional[dict] = None
    packages: tuple = ()

    @property
    def archive_url(self) -> str:
        base = urllib.parse.urljoin(self.manifest_url, self.archive_path)
        return _append_query(base, "v", self.updated_at)

    def find_package(self, category: str, key: str) -> Optional[RemotePackage]:
        for pkg in self.packages:
            if pkg.category == category and pkg.key == key:
                return pkg
        return None


def _append_query(url: str, key: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{key}={urllib.parse.quote(value, safe='')}"


def _fetch_bytes(url: str, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(DOWNLOAD_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def is_safe_bundle_name(name: str) -> bool:
    """True for a name usable verbatim as a directory under devices/: no path
    separators or traversal, no trailing space/dot (Windows strips them), no
    reserved device name (CON, COM1, ...)."""
    if not SAFE_BUNDLE_NAME.fullmatch(name):
        return False
    if name.endswith(" ") or name.endswith("."):
        return False
    if name.split(".")[0].rstrip(" ").upper() in _WINDOWS_RESERVED_NAMES:
        return False
    return name not in {".", ".."}


def is_large_download(archive_size: Optional[int]) -> bool:
    """True when a bundle/package's compressed download crosses the GUI
    large-download threshold. Unknown size (None) is treated as not large."""
    return isinstance(archive_size, int) and archive_size >= LARGE_DOWNLOAD_THRESHOLD


def parse_version_tuple(text) -> Optional[tuple]:
    """Parse a dotted version ('3.20', '3.20.1') into a tuple of ints, taking
    the leading numeric components and stopping at the first non-numeric one.
    Returns None when no leading numeric component exists."""
    if not isinstance(text, str):
        return None
    parts: List[int] = []
    for token in text.strip().split("."):
        token = token.strip()
        if not token.isdigit():
            break
        parts.append(int(token))
    return tuple(parts) if parts else None


def _parse_packages(bundle_name: str, raw, manifest_url: str) -> tuple:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise BundleError(f"bundle {bundle_name}: malformed additional_packages")
    parsed: List[RemotePackage] = []
    for category, entries in raw.items():
        if not isinstance(category, str) or not category.strip():
            raise BundleError(f"bundle {bundle_name}: malformed package category")
        if not isinstance(entries, list):
            raise BundleError(
                f"bundle {bundle_name}: package category {category} is not a list")
        for item in entries:
            if not isinstance(item, dict):
                raise BundleError(
                    f"bundle {bundle_name}: malformed package entry in {category}")
            file_key = item.get("file")
            dir_key = item.get("directory")
            if isinstance(file_key, str) and not isinstance(dir_key, str):
                key, is_directory = file_key, False
            elif isinstance(dir_key, str) and not isinstance(file_key, str):
                key, is_directory = dir_key, True
            else:
                raise BundleError(
                    f"bundle {bundle_name}: package in {category} needs exactly "
                    f"one of file/directory")
            # The key lands on the local filesystem inside the device dir;
            # reject anything that could escape it.
            if not is_safe_bundle_name(key):
                raise BundleError(
                    f"bundle {bundle_name}: unsafe package artifact name: {key!r}")
            archive_path = item.get("archive_path")
            if not isinstance(archive_path, str) or not archive_path:
                raise BundleError(
                    f"bundle {bundle_name}: package {category}/{key} has no "
                    f"archive_path")
            display = item.get("name")
            parsed.append(RemotePackage(
                category=category,
                key=key,
                is_directory=is_directory,
                name=display if isinstance(display, str) and display else key,
                archive_path=archive_path,
                manifest_url=manifest_url,
                archive_sha256=item.get("archive_sha256")
                if isinstance(item.get("archive_sha256"), str) else None,
                archive_size=item.get("archive_size")
                if isinstance(item.get("archive_size"), int) else None,
                unpacked_size=item.get("unpacked_size")
                if isinstance(item.get("unpacked_size"), int) else None,
            ))
    return tuple(parsed)


def _parse_abuse_email(manifest: dict) -> Optional[str]:
    value = manifest.get("abuse_email")
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _fetch_repo_bundles(base_url: str) -> Tuple[List[RemoteBundle], Optional[str]]:
    manifest_url = manifest_url_for(base_url)
    fresh_url = _append_query(manifest_url, "cb", str(int(time.time())))
    try:
        raw = _fetch_bytes(fresh_url)
        manifest = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise BundleError(f"failed to download remote manifest: {exc}") from exc

    version = manifest.get("version")
    if not isinstance(version, int):
        raise BundleError("remote manifest has no integer version")
    if version != SUPPORTED_REMOTE_MANIFEST_VERSION:
        raise ManifestVersionError(version, SUPPORTED_REMOTE_MANIFEST_VERSION)

    bundles = manifest.get("bundles")
    if not isinstance(bundles, list):
        raise BundleError("remote manifest has no bundles list")

    parsed: List[RemoteBundle] = []
    for item in bundles:
        if not isinstance(item, dict):
            raise BundleError("remote manifest contains a malformed entry")
        name = item.get("name")
        updated_at = item.get("updated_at")
        archive_path = item.get("archive_path")
        if not isinstance(name, str) or not is_safe_bundle_name(name):
            raise BundleError(f"remote manifest contains unsafe name: {name!r}")
        if not isinstance(updated_at, str) or not updated_at:
            raise BundleError(f"bundle {name} has no updated_at")
        if not isinstance(archive_path, str) or not archive_path:
            raise BundleError(f"bundle {name} has no archive_path")
        parsed.append(RemoteBundle(
            name=name,
            repo_url=base_url,
            updated_at=updated_at,
            archive_path=archive_path,
            manifest_url=manifest_url,
            archive_sha256=item.get("archive_sha256") if isinstance(item.get("archive_sha256"), str) else None,
            archive_size=item.get("archive_size") if isinstance(item.get("archive_size"), int) else None,
            unpacked_size=item.get("unpacked_size") if isinstance(item.get("unpacked_size"), int) else None,
            cerf_json=item.get("cerf_json") if isinstance(item.get("cerf_json"), dict) else None,
            packages=_parse_packages(name, item.get("additional_packages"), manifest_url),
        ))
    return parsed, _parse_abuse_email(manifest)


def _fetch_repo_analytics(base_url: str) -> dict:
    """Download one repo's analytics.json and return
    {(repo_url, name): place}."""
    url = _append_query(analytics_url_for(base_url), "cb", str(int(time.time())))
    raw = _fetch_bytes(url)
    data = json.loads(raw.decode("utf-8"))
    per_rom = data.get("per_rom")
    if not isinstance(per_rom, list):
        raise BundleError("analytics.json has no per_rom list")
    places: dict = {}
    for entry in per_rom:
        if not isinstance(entry, dict):
            raise BundleError("analytics.json contains a malformed entry")
        name = entry.get("name")
        place = entry.get("place")
        if not isinstance(name, str) or not name:
            raise BundleError("analytics.json entry has no name")
        if not isinstance(place, int) or isinstance(place, bool):
            raise BundleError(f"analytics.json entry {name} has no integer place")
        places[(base_url, name)] = place
    return places


def load_analytics(repositories: List[BundleRepository]) -> Optional[dict]:
    """Merge every enabled repo's download-rank analytics into one
    {(repo_url, name): place} map. Returns None when any enabled repo's
    analytics.json is absent or unparseable - the download-count sort is a
    single ordering over all repos, so one bad source disables it rather than
    mixing ranked and unranked repos."""
    merged: dict = {}
    for repo in repositories:
        if not repo.enabled:
            continue
        try:
            merged.update(_fetch_repo_analytics(repo.url))
        except Exception:
            return None
    return merged


def load_merged_manifest(
        repositories: List[BundleRepository],
) -> Tuple[List[RemoteBundle], List[Tuple[str, str]], Dict[str, str]]:
    """Fetch every enabled repo's manifest. Returns the merged bundles, the
    per-repo (url, error) failures, and each repo's published copyright-removal
    contact keyed by repository URL. When NO repo could be fetched at all the
    first failure is raised so the GUI surfaces it as the refresh error.
    A manifest-version mismatch always raises - it carries the upgrade
    notice."""
    all_bundles: List[RemoteBundle] = []
    errors: List[Tuple[str, str]] = []
    abuse_emails: Dict[str, str] = {}
    first_exc: Optional[Exception] = None
    fetched = 0
    for repo in repositories:
        if not repo.enabled:
            continue
        try:
            bundles, abuse_email = _fetch_repo_bundles(repo.url)
            all_bundles.extend(bundles)
            if abuse_email is not None:
                abuse_emails[repo.url] = abuse_email
            fetched += 1
        except ManifestVersionError:
            raise
        except Exception as exc:
            if first_exc is None:
                first_exc = exc
            errors.append((repo.url, str(exc)))
    if not fetched and first_exc is not None:
        raise first_exc
    all_bundles.sort(key=lambda b: b.name.lower())
    return all_bundles, errors, abuse_emails
