from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, Optional

from bundles import BundleError
from device_state import format_size
from available_update import AvailableUpdate
from bundle_download import safe_extract, stream_download
from upgrade_process import (UPGRADE_DIR_NAME, UPGRADE_ZIP_NAME, UpgradeError,
                             launcher_exe_in)

LogFn = Callable[[str], None]
ProgressFn = Callable[[str, int, Optional[int]], None]


def _wipe(path: Path) -> None:
    try:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    except OSError as exc:
        raise UpgradeError(f"cannot remove {path}: {exc}") from exc


def download_upgrade(release: AvailableUpdate, install_dir: Path,
                     log: LogFn, progress: ProgressFn) -> Path:
    upgrade_dir = install_dir / UPGRADE_DIR_NAME
    zip_path = install_dir / UPGRADE_ZIP_NAME

    log(f"Preparing {upgrade_dir}")
    _wipe(upgrade_dir)
    _wipe(zip_path)

    log(f"Downloading {release.asset_name} {format_size(release.asset_size)}")
    try:
        stream_download(release.asset_url, zip_path, "Downloading",
                         release.asset_size, progress, None)
    except BundleError as exc:
        raise UpgradeError(f"download failed: {exc}") from exc
    except OSError as exc:
        raise UpgradeError(f"download failed: {exc}") from exc

    log("Unpacking the archive")
    progress("Unpacking", 0, None)
    upgrade_dir.mkdir(parents=True)
    try:
        safe_extract(zip_path, upgrade_dir)
    except (BundleError, OSError) as exc:
        raise UpgradeError(f"unpacking failed: {exc}") from exc

    _wipe(zip_path)

    if not launcher_exe_in(upgrade_dir).is_file():
        raise UpgradeError(
            f"{release.asset_name} contains no launcher.exe")

    log(f"Staged the new build in {upgrade_dir}")
    return upgrade_dir
