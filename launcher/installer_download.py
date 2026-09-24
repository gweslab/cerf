from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from bundles import BundleError
from update_channel_stable import fetch_latest_release
from update_channel_unstable import fetch_latest_ci_build
from upgrade_download import download_upgrade
from upgrade_process import UpgradeError

LogFn = Callable[[str], None]
ProgressFn = Callable[[str, int, Optional[int]], None]


def stage_release(install_dir: Path, log: LogFn, progress: ProgressFn,
                  unstable: bool) -> str:
    try:
        release = fetch_latest_ci_build() if unstable \
            else fetch_latest_release()
    except BundleError as exc:
        raise UpgradeError("cannot reach the CERF {} feed: {}".format(
            "unstable build" if unstable else "release", exc))

    log("Latest {}: CE Runtime Foundation {}".format(
        "unstable build" if unstable else "release", release.tag))
    try:
        install_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise UpgradeError("cannot create {}: {}".format(install_dir, exc))

    download_upgrade(release, install_dir, log, progress)
    return release.tag
