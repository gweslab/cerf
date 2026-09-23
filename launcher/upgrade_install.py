from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, List

from bundle_repositories import MAIN_REPOSITORY_URL
from bundles import BundleError, is_safe_bundle_name
from cerf_json_merge import migrate_cerf_json
from cerf_user_json import (LauncherLink, read_launcher_link,
                            write_launcher_link)
from device_state import load_local_manifest
from retry_gate import RetryFn, attempt
from upgrade_process import GLOBAL_CONFIG_NAME, UpgradeError

LogFn = Callable[[str], None]


def migrate_device_links(devices_dir: Path, log: LogFn) -> None:
    """Pre-link-era installs: a device recorded in devices/manifest.json was
    downloaded by the launcher, and the main repository was the only source
    that existed before the cerf-user.json launcher block - so every recorded
    directory without a link block is linked to the main repository under its
    own name. Wizard/hand-made devices are not in the manifest and stay
    untouched."""
    try:
        installed = load_local_manifest(devices_dir / "manifest.json")
    except BundleError as exc:
        log(f"  device-link migration skipped: {exc}")
        return
    for dir_name in installed:
        device_dir = devices_dir / dir_name
        if not device_dir.is_dir() or not is_safe_bundle_name(dir_name):
            continue
        if read_launcher_link(device_dir) is not None:
            continue
        log(f"  linking devices/{dir_name} to the main repository")
        try:
            write_launcher_link(
                device_dir, LauncherLink(MAIN_REPOSITORY_URL, dir_name))
        except OSError as exc:
            log(f"  devices/{dir_name}: link not written ({exc})")


def _payload_files(upgrade_dir: Path) -> List[Path]:
    files = [p for p in sorted(upgrade_dir.rglob("*")) if p.is_file()]
    return [p for p in files
            if p.relative_to(upgrade_dir).as_posix() != GLOBAL_CONFIG_NAME]


def _copy_with_retry(source: Path, destination: Path, what: str,
                     ask_retry: RetryFn) -> None:
    def copy() -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    error = attempt("Copy failed", f"Copying {what}", copy, ask_retry)
    if error is not None:
        raise UpgradeError(f"copying {what} was cancelled") from error


def install_upgrade(upgrade_dir: Path, install_dir: Path, log: LogFn,
                    ask_retry: RetryFn) -> None:
    payload = _payload_files(upgrade_dir)
    log(f"Installing {len(payload)} file(s) into {install_dir}")
    for source in payload:
        relative = source.relative_to(upgrade_dir)
        log(f"  {relative.as_posix()}")
        _copy_with_retry(source, install_dir / relative, relative.as_posix(),
                         ask_retry)

    staged_config = upgrade_dir / GLOBAL_CONFIG_NAME
    if not staged_config.is_file():
        raise UpgradeError(f"the new build ships no {GLOBAL_CONFIG_NAME}")
    log(f"Migrating {GLOBAL_CONFIG_NAME}")
    error = attempt("Migration failed", f"Migrating {GLOBAL_CONFIG_NAME}",
                    lambda: migrate_cerf_json(staged_config,
                                              install_dir / GLOBAL_CONFIG_NAME),
                    ask_retry, errors=(OSError, ValueError))
    if error is not None:
        raise UpgradeError(
            f"migrating {GLOBAL_CONFIG_NAME} was cancelled") from error

    log("Migrating device repository links")
    migrate_device_links(install_dir / "devices", log)
    log("Installation complete")
