from __future__ import annotations

import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from bundle_download import CancelledError, ProgressFn
from bundles import BundleError, DOWNLOAD_CHUNK, is_safe_bundle_name
from cerf_user_json import CERF_USER_JSON_FILENAME
from device_state import write_cerf_json


@dataclass(frozen=True)
class UserDeviceSpec:
    name: str
    board_id: str
    rom_files: Dict[str, Path]
    storage: Dict[str, str]
    copy_rom: bool


def validate_device_name(devices_dir: Path, name: str) -> Optional[str]:
    """None when `name` can become a device directory; otherwise the
    user-facing rejection reason."""
    if not name.strip():
        return "Enter a device name."
    if not is_safe_bundle_name(name):
        return (f"'{name}' cannot be used as a device directory name.\n\n"
                f"Use letters, digits, spaces, dots, dashes or underscores; "
                f"it must start with a letter or digit and must not end with "
                f"a space or dot.")
    if (devices_dir / name).exists():
        return (f"devices/{name} already exists.\n\n"
                f"Pick a different name.")
    return None


def _copy_with_progress(src: Path, dst: Path, label: str,
                        progress: ProgressFn,
                        cancel_event: Optional[threading.Event]) -> None:
    total = src.stat().st_size
    done = 0
    progress(label, 0, total)
    with src.open("rb") as fin, dst.open("wb") as fout:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise CancelledError(f"{label}: cancelled")
            chunk = fin.read(DOWNLOAD_CHUNK)
            if not chunk:
                break
            fout.write(chunk)
            done += len(chunk)
            progress(label, done, total)


def create_user_device(devices_dir: Path, spec: UserDeviceSpec,
                       progress: ProgressFn,
                       cancel_event: Optional[threading.Event]) -> str:
    """Create the device directory; returns its name. The directory is
    removed again when creation fails or is cancelled partway."""
    reason = validate_device_name(devices_dir, spec.name)
    if reason is not None:
        raise BundleError(reason)
    for path in spec.rom_files.values():
        if not path.is_file():
            raise BundleError(f"ROM file not found: {path}")
    if spec.copy_rom:
        names = [p.name.casefold() for p in spec.rom_files.values()]
        if len(set(names)) != len(names):
            raise BundleError("Two ROM files have the same name, so both "
                              "cannot be copied to the device directory.")

    target = devices_dir / spec.name
    target.mkdir(parents=True)
    try:
        rom: Dict[str, str] = {}
        for key, path in spec.rom_files.items():
            if spec.copy_rom:
                _copy_with_progress(path, target / path.name,
                                    f"Copying {path.name}",
                                    progress, cancel_event)
                rom[key] = path.name
            else:
                rom[key] = str(path)
        obj: dict = {
            "meta": {"name": spec.name},
            "rom": rom,
            "board": {"id": spec.board_id},
        }
        if spec.storage:
            obj["storage"] = dict(spec.storage)
        write_cerf_json(target / CERF_USER_JSON_FILENAME, obj)
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    return spec.name
