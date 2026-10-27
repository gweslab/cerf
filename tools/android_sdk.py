from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import verified_download

NDK_VERSION = "29.0.14206865"
BUILD_TOOLS_VERSION = "36.0.0"
MIN_SDK = 29
TARGET_SDK = 36
LINUX_CMDLINE_TOOLS_URL = "https://dl.google.com/android/repository/commandlinetools-linux-16111833_latest.zip"
LINUX_CMDLINE_TOOLS_SHA256 = "0877a1d048fe4a24efe2eff536ca4223f7adeb58648bb81909d33c446918cfa8"


def platform_name(api: int) -> str:
    return "android-{}".format(api)


def packages() -> List[str]:
    return ["platforms;" + platform_name(TARGET_SDK), "build-tools;" + BUILD_TOOLS_VERSION, "ndk;" + NDK_VERSION]


def fetch_linux_cmdline_tools(destination: Path) -> Path:
    return verified_download.fetch_verified(LINUX_CMDLINE_TOOLS_URL, destination, LINUX_CMDLINE_TOOLS_SHA256, print)


def main(argv: List[str]) -> int:
    if argv[1:] == ["--packages"]:
        print(" ".join(packages()))
        return 0
    if len(argv) == 3 and argv[1] == "--fetch-linux-cmdline-tools":
        try:
            fetch_linux_cmdline_tools(Path(argv[2]))
        except verified_download.DownloadError as exc:
            sys.stderr.write("{}\n".format(exc))
            return 1
        return 0
    sys.stderr.write("usage: android_sdk.py --packages | --fetch-linux-cmdline-tools <zip>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
