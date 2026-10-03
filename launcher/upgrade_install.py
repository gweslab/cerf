from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, List

from cerf_json_merge import migrate_cerf_json
from retry_gate import RetryFn, attempt
from upgrade_process import GLOBAL_CONFIG_NAME, UpgradeError

LogFn = Callable[[str], None]


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

    log("Installation complete")
