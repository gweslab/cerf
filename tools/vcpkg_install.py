from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Callable, Dict, List

from host_branch import ANDROID_AMD64, ANDROID_ARM64, WIN32_X86
from tool_process import run_or_raise

TRIPLETS = {WIN32_X86: "x86-windows-static-md", ANDROID_ARM64: "arm64-android", ANDROID_AMD64: "x64-android"}


class VcpkgError(Exception):
    pass


def installed_root(repo: Path, triplet: str) -> Path:
    return repo / "vcpkg_installed" / triplet


def installed_prefix(repo: Path, triplet: str) -> Path:
    return installed_root(repo, triplet) / triplet


def integration_props() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", "")) / "vcpkg" / "vcpkg.user.props"


def integrated_root() -> Path:
    props = integration_props().read_text(encoding="utf-8-sig", errors="replace")
    match = re.search(r'Project="([^"]+)\\scripts\\buildsystems\\msbuild\\vcpkg\.props"', props)
    if match is None:
        raise VcpkgError("vcpkg.user.props names no vcpkg root. Run 'vcpkg integrate install' again.")
    return Path(match.group(1))


def vcpkg_root(branch_name: str) -> Path:
    if branch_name == WIN32_X86:
        return integrated_root()
    for name in ("VCPKG_ROOT", "VCPKG_INSTALLATION_ROOT"):
        value = os.environ.get(name)
        if value:
            return Path(value)
    if os.name == "nt":
        return integrated_root()
    raise VcpkgError("Set VCPKG_ROOT to a vcpkg checkout.")


def executable(root: Path) -> Path:
    return root / ("vcpkg.exe" if os.name == "nt" else "vcpkg")


def install(repo: Path, vcpkg_root: Path, triplet: str, env: Dict[str, str],
            heartbeat: Callable[[], None]) -> Path:
    installed = installed_root(repo, triplet)
    stamp = installed / ".msbuildstamp-{}.stamp".format(triplet)
    inputs = [repo / "vcpkg.json", repo / "vcpkg-configuration.json"]
    inputs += [p for p in (repo / "libCerfCore" / "vcpkg-ports").rglob("*") if p.is_file()]
    current = stamp.is_file() and \
        not any(p.stat().st_mtime > stamp.stat().st_mtime for p in inputs)
    if current:
        return installed_prefix(repo, triplet)
    print("[VCPKG] Installing the manifest dependencies ({})".format(triplet), flush=True)
    run_or_raise([executable(vcpkg_root), "install", "--x-wait-for-lock", "--triplet", triplet,
                  "--vcpkg-root", vcpkg_root, "--x-manifest-root={}".format(repo),
                  "--x-install-root={}".format(installed)], VcpkgError, "vcpkg install", env=env)
    heartbeat()
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.touch()
    return installed_prefix(repo, triplet)


def main(argv: List[str]) -> int:
    if len(argv) == 3 and argv[1] == "--outputs":
        print("triplet={}".format(TRIPLETS[argv[2]]))
        return 0
    if len(argv) == 3 and argv[1] == "--install":
        try:
            install(Path(__file__).resolve().parent.parent, vcpkg_root(argv[2]), TRIPLETS[argv[2]],
                    dict(os.environ), lambda: None)
        except (VcpkgError, OSError) as exc:
            print("[VCPKG] FAILED! {}".format(exc), flush=True)
            return 1
        return 0
    sys.stderr.write("usage: vcpkg_install.py --outputs <host branch> | --install <host branch>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
