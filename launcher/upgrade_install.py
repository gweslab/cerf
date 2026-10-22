from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable, List

from cerf_json_merge import migrate_cerf_json
from retry_gate import RetryFn, attempt
from upgrade_process import GLOBAL_CONFIG_NAME, UpgradeError

LogFn = Callable[[str], None]
BUNDLE_SUFFIX = ".app"


def _bundles(upgrade_dir: Path) -> List[Path]:
    return sorted(p for p in upgrade_dir.iterdir()
                  if p.suffix == BUNDLE_SUFFIX and p.is_dir() and not p.is_symlink())


def _payload_files(upgrade_dir: Path) -> List[Path]:
    entries: List[Path] = []
    for directory, dirnames, filenames in os.walk(str(upgrade_dir)):
        base = Path(directory)
        if base == upgrade_dir:
            dirnames[:] = [d for d in dirnames if not d.endswith(BUNDLE_SUFFIX)]
        entries += [base / d for d in dirnames if (base / d).is_symlink()]
        entries += [base / f for f in filenames]
    return sorted(p for p in entries
                  if p.relative_to(upgrade_dir).as_posix() != GLOBAL_CONFIG_NAME)


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(str(path))
    elif path.is_symlink() or path.exists():
        path.unlink()


def _copy_entry(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        _remove(destination)
        os.symlink(os.readlink(str(source)), str(destination))
    else:
        shutil.copy2(str(source), str(destination))


def _replace_bundle(source: Path, destination: Path) -> None:
    _remove(destination)
    shutil.copytree(str(source), str(destination), symlinks=True)


def _with_retry(action: Callable[[], None], what: str, ask_retry: RetryFn) -> None:
    error = attempt("Copy failed", f"Copying {what}", action, ask_retry)
    if error is not None:
        raise UpgradeError(f"copying {what} was cancelled") from error


def install_upgrade(upgrade_dir: Path, install_dir: Path, log: LogFn,
                    ask_retry: RetryFn) -> None:
    bundles = _bundles(upgrade_dir)
    payload = _payload_files(upgrade_dir)
    log(f"Installing {len(bundles)} application(s) and {len(payload)} file(s) into "
        f"{install_dir}")
    for source in bundles:
        log(f"  {source.name}")
        _with_retry(lambda: _replace_bundle(source, install_dir / source.name),
                    source.name, ask_retry)
    for source in payload:
        relative = source.relative_to(upgrade_dir)
        log(f"  {relative.as_posix()}")
        _with_retry(lambda: _copy_entry(source, install_dir / relative),
                    relative.as_posix(), ask_retry)

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

    log("Installation complete")
