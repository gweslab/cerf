"""Local device state: per-device metadata (cerf.json), package install
status, and the local install manifest with its additional-package nesting."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from bundles import (
    BundleError,
    RemoteBundle,
    RemotePackage,
    package_category_label,
)


STATE_INSTALLED = "Installed"
STATE_UPDATE    = "Update available"
STATE_CONFIG    = "Device pending update"
STATE_AVAILABLE = "Available"
STATE_USER      = "User device"

# Mirrors CERF's kDefaultStateFile (cerf/state/state_image_format.h): the
# hibernation .img cerf.exe writes/reads in each device directory.
STATE_IMAGE_FILENAME = "state.img"

# Saved-state preview PNG cerf.exe writes beside state.img on a successful
# hibernation save (cerf/state/hibernation.cpp Hibernation::Save).
SAVED_STATE_SCREENSHOT_FILENAME = "saved_state.png"

# Live preview PNG cerf.exe refreshes periodically while running
# (cerf/host/live_screenshot_reporter.cpp).
LIVE_STATE_SCREENSHOT_FILENAME = "live_state.png"


@dataclass
class DeviceSource:
    """Who preserved/provided this ROM bundle. Optional in the manifest; when
    present, `name` is mandatory. The three links are each optional."""

    name: str = ""
    website: str = ""   # "pay them a visit" target
    donate: str = ""    # "support them" target
    origin: str = ""    # "Source data link" target (where the ROM came from)

    @property
    def has_links(self) -> bool:
        return bool(self.website or self.donate or self.origin)


@dataclass
class DeviceMeta:
    name: str = ""
    device_name: str = ""
    board_id: str = ""
    os_name: str = ""
    os_ver_major: int = 0
    os_ver_minor: int = 0
    os_ver_build: int = 0
    os_language: str = ""
    device_year: int = 0
    os_year: int = 0
    os_notes: List[str] = field(default_factory=list)
    description: str = ""
    notes: List[str] = field(default_factory=list)
    source: Optional[DeviceSource] = None
    forbid_guest_additions: bool = False

    @property
    def os_version(self) -> str:
        if self.os_name and (self.os_ver_major or self.os_ver_minor):
            ver = f"CE {self.os_ver_major}.{self.os_ver_minor}"
            if self.os_ver_build:
                ver += f".{self.os_ver_build}"
            return f"{self.os_name} ({ver})"
        if self.os_name:
            return self.os_name
        return ""


@dataclass
class PackageStatus:
    """One additional package of one device, with its local install state.
    Freshness follows the ROM pattern: the archive sha256 recorded at install
    time is compared against the remote manifest's current sha256."""

    remote: RemotePackage
    installed: bool
    installed_sha256: Optional[str] = None

    @property
    def has_update(self) -> bool:
        return (self.installed
                and self.installed_sha256 is not None
                and self.remote.archive_sha256 is not None
                and self.installed_sha256.lower() != self.remote.archive_sha256.lower())

    @property
    def category_label(self) -> str:
        return package_category_label(self.remote.category)

    @property
    def state_label(self) -> str:
        if self.has_update:
            return STATE_UPDATE
        if self.installed:
            return STATE_INSTALLED
        return STATE_AVAILABLE


@dataclass
class DeviceBundle:
    """One row of the device model. `name` is the device DIRECTORY name for
    installed devices and the remote bundle name for not-yet-installed ones;
    `key` is the unique UI identity (equals `name` for installed devices,
    carries the repository URL for remote-only ones, where two repositories
    may publish the same bundle name)."""

    name: str
    remote: Optional[RemoteBundle]
    local_dir_exists: bool
    installed_sha256: Optional[str]
    meta: DeviceMeta = field(default_factory=DeviceMeta)
    default_screen_width: Optional[int] = None
    default_screen_height: Optional[int] = None
    packages: List[PackageStatus] = field(default_factory=list)
    key: str = ""
    # Size of the local rom.primary file; the card's size fallback for
    # devices with no remote (a remote bundle shows its unpacked_size).
    rom_size: Optional[int] = None
    # Set only when on-disk cerf.json differs from the remote and no ROM
    # update is pending.
    cerf_json_pending: bool = False

    def __post_init__(self) -> None:
        if not self.key:
            self.key = self.name

    @property
    def is_installed(self) -> bool:
        return self.local_dir_exists

    @property
    def is_user_device(self) -> bool:
        return self.local_dir_exists and self.remote is None

    @property
    def has_update(self) -> bool:
        return (self.local_dir_exists
                and self.remote is not None
                and self.installed_sha256 is not None
                and self.remote.archive_sha256 is not None
                and self.installed_sha256.lower() != self.remote.archive_sha256.lower())

    @property
    def has_cerf_json_update(self) -> bool:
        return self.cerf_json_pending

    @property
    def state_label(self) -> str:
        if self.is_user_device:
            return STATE_USER
        if self.has_update:
            return STATE_UPDATE
        if self.has_cerf_json_update:
            return STATE_CONFIG
        if self.is_installed:
            return STATE_INSTALLED
        return STATE_AVAILABLE

    @property
    def has_package_updates(self) -> bool:
        return any(p.has_update for p in self.packages)


def package_artifact_present(device_dir: Path, pkg: RemotePackage) -> bool:
    path = device_dir / pkg.key
    if pkg.is_directory:
        if not path.is_dir():
            return False
        for _ in path.iterdir():
            return True
        return False
    return path.is_file()


@dataclass
class SavedStateInfo:
    saved_at: float  # state.img mtime, epoch seconds
    size: int        # state.img size in bytes


def saved_state_info(device_dir: Path) -> Optional[SavedStateInfo]:
    """Hibernation snapshot for a device, or None when no state.img exists."""
    path = device_dir / STATE_IMAGE_FILENAME
    if not path.is_file():
        return None
    try:
        st = path.stat()
    except OSError:
        return None
    return SavedStateInfo(saved_at=st.st_mtime, size=st.st_size)


CERF_STATUS_FILENAME = "cerf-status.json"
RUNNING_STALE_SECONDS = 7.0


@dataclass
class RunningStatus:
    pid: int
    hwnd: int
    heartbeat_unix: int
    started_unix: int


def running_status(device_dir: Path) -> Optional[RunningStatus]:
    obj = _load_json_object(device_dir / CERF_STATUS_FILENAME)
    if obj is None:
        return None
    hb = obj.get("heartbeat_unix")
    if not isinstance(hb, (int, float)) or isinstance(hb, bool):
        return None
    if time.time() - float(hb) >= RUNNING_STALE_SECONDS:
        return None

    def _int(v) -> int:
        return v if isinstance(v, int) and not isinstance(v, bool) else 0

    return RunningStatus(pid=_int(obj.get("pid")), hwnd=_int(obj.get("hwnd")),
                         heartbeat_unix=int(hb),
                         started_unix=_int(obj.get("started_unix")))


def format_size(n: Optional[int]) -> str:
    if not isinstance(n, int) or n <= 0:
        return ""
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.1f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} B"


def parse_cerf_json_object(obj) -> tuple[DeviceMeta, Optional[int], Optional[int]]:
    meta = DeviceMeta()
    width: Optional[int] = None
    height: Optional[int] = None
    if not isinstance(obj, dict):
        return meta, None, None

    m = obj.get("meta")
    if isinstance(m, dict):
        meta.name = _str_or_empty(m.get("name"))
        meta.device_name = _str_or_empty(m.get("device_name"))
        meta.device_year = _int_or_zero(m.get("device_year"))
        meta.description = _str_or_empty(m.get("description"))
        meta.notes = _str_list(m.get("notes"))
        src_block = m.get("source")
        if isinstance(src_block, dict):
            # source.name is mandatory when the source block exists; without it
            # the block is meaningless, so an unnamed source is ignored.
            src_name = _str_or_empty(src_block.get("name"))
            if src_name:
                meta.source = DeviceSource(
                    name=src_name,
                    website=_str_or_empty(src_block.get("website")),
                    donate=_str_or_empty(src_block.get("donate")),
                    origin=_str_or_empty(src_block.get("origin")),
                )
        os_block = m.get("os")
        if isinstance(os_block, dict):
            meta.os_name = _str_or_empty(os_block.get("name"))
            meta.os_ver_major = _int_or_zero(os_block.get("ver_major"))
            meta.os_ver_minor = _int_or_zero(os_block.get("ver_minor"))
            meta.os_ver_build = _int_or_zero(os_block.get("ver_build"))
            meta.os_language = _str_or_empty(os_block.get("language"))
            meta.os_year = _int_or_zero(os_block.get("year"))
            meta.os_notes = _str_list(os_block.get("notes"))

    launcher = obj.get("launcher")
    if isinstance(launcher, dict):
        meta.forbid_guest_additions = launcher.get("forbid_guest_additions") is True

    board = obj.get("board")
    if isinstance(board, dict):
        meta.board_id = _str_or_empty(board.get("id"))
        w = board.get("configurable_screen_width")
        h = board.get("configurable_screen_height")
        if isinstance(w, int) and w > 0:
            width = w
        if isinstance(h, int) and h > 0:
            height = h

    return meta, width, height


def _str_or_empty(v) -> str:
    return v if isinstance(v, str) else ""


def _int_or_zero(v) -> int:
    return v if isinstance(v, int) else 0


def _str_list(v) -> List[str]:
    if not isinstance(v, list):
        return []
    return [s for s in v if isinstance(s, str) and s.strip()]


def write_cerf_json(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def _load_json_object(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def cerf_json_differs(path: Path, obj: dict) -> bool:
    """True when the on-disk cerf.json parses to something other than obj.
    Comparison is semantic (parsed JSON): reformatting / key reordering never
    counts; a missing or corrupt file counts as differing."""
    try:
        with path.open("r", encoding="utf-8") as f:
            existing = json.load(f)
    except (OSError, json.JSONDecodeError):
        existing = None
    return existing != obj


@dataclass
class LocalPackageRecord:
    category: str
    key: str
    is_directory: bool
    sha256: str


@dataclass
class LocalBundleRecord:
    # None when the device dir was placed by hand and only a package was ever
    # installed through the launcher; ROM freshness is then unknown.
    updated_at: Optional[str] = None
    sha256: Optional[str] = None
    packages: List[LocalPackageRecord] = field(default_factory=list)

    def find_package(self, category: str, key: str) -> Optional[LocalPackageRecord]:
        for rec in self.packages:
            if rec.category == category and rec.key == key:
                return rec
        return None

    def drop_package(self, category: str, key: str) -> None:
        self.packages = [r for r in self.packages
                         if not (r.category == category and r.key == key)]


def _parse_local_packages(raw) -> List[LocalPackageRecord]:
    out: List[LocalPackageRecord] = []
    if not isinstance(raw, dict):
        return out
    for category, entries in raw.items():
        if not isinstance(category, str) or not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            sha = item.get("sha256")
            if not isinstance(sha, str) or not sha:
                continue
            file_key = item.get("file")
            dir_key = item.get("directory")
            if isinstance(file_key, str) and file_key:
                out.append(LocalPackageRecord(category, file_key, False, sha))
            elif isinstance(dir_key, str) and dir_key:
                out.append(LocalPackageRecord(category, dir_key, True, sha))
    return out


def load_local_manifest(local_manifest_path: Path) -> Dict[str, LocalBundleRecord]:
    if not local_manifest_path.exists():
        return {}
    try:
        with local_manifest_path.open("r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as exc:
        raise BundleError(f"failed to read local manifest: {exc}") from exc

    installed: Dict[str, LocalBundleRecord] = {}
    bundles = manifest.get("bundles") if isinstance(manifest, dict) else None
    if isinstance(bundles, list):
        for item in bundles:
            if not isinstance(item, dict):
                continue
            n = item.get("name")
            if not isinstance(n, str):
                continue
            u = item.get("updated_at")
            s = item.get("sha256")
            installed[n] = LocalBundleRecord(
                updated_at=u if isinstance(u, str) else None,
                sha256=s if isinstance(s, str) and s else None,
                packages=_parse_local_packages(item.get("additional_packages")),
            )
    elif isinstance(bundles, dict):
        # Legacy pre-list format: {"name": "<updated_at>"} or nested dicts.
        for n, v in bundles.items():
            if isinstance(v, dict) and isinstance(v.get("updated_at"), str):
                installed[str(n)] = LocalBundleRecord(updated_at=v["updated_at"])
            elif isinstance(v, str):
                installed[str(n)] = LocalBundleRecord(updated_at=v)
    return installed


def save_local_manifest(local_manifest_path: Path,
                        installed: Dict[str, LocalBundleRecord]) -> None:
    bundles = []
    for name in sorted(installed, key=str.lower):
        record = installed[name]
        entry: dict = {"name": name}
        if record.updated_at is not None:
            entry["updated_at"] = record.updated_at
        if record.sha256 is not None:
            entry["sha256"] = record.sha256
        if record.packages:
            # Mirrors the remote manifest's additional_packages nesting.
            categories: Dict[str, list] = {}
            for rec in record.packages:
                identity = "directory" if rec.is_directory else "file"
                categories.setdefault(rec.category, []).append(
                    {identity: rec.key, "sha256": rec.sha256})
            entry["additional_packages"] = categories
        bundles.append(entry)
    payload = {"bundles": bundles}
    tmp = local_manifest_path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    os.replace(tmp, local_manifest_path)
