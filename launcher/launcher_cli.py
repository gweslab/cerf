"""The `launcher sync` command-line interface."""
from __future__ import annotations

import argparse
import subprocess
import sys
import threading
from pathlib import Path
from typing import List, Optional, Tuple

from app_paths import resolve_cerf_exe
from bundles import BundleError, package_category_label
from device_source_text import source_credit
from device_state import DeviceBundle, format_size
from operations import BundleManager


def _cli_progress(label: str, done: int, total: Optional[int]) -> None:
    if total:
        pct = int(done * 100 / total)
        print(f"\r{label}: {pct}%  ({done:,} / {total:,})", end="", flush=True)
    else:
        print(f"\r{label}: {done:,} bytes", end="", flush=True)


def _print_rom_license_notice(target: str) -> None:
    print(
        f"NOTICE: ROM bundles and add-on packages distributed by this "
        f"launcher are abandonware/released publicly by their respective "
        f"OEMs and remain their property. By downloading {target} you take "
        f"full personal responsibility and accept whatever license or terms "
        f"the OEM applied when releasing it. The CERF project gives no "
        f"warranty, grants no license, and accepts no liability for the "
        f"contents.\n"
    )


def _print_source_notice(device: DeviceBundle) -> None:
    src = device.meta.source
    if src is None:
        return
    print(source_credit(src))
    if src.website:
        print(f"  Visit them:   {src.website}")
    if src.donate:
        print(f"  Support them: {src.donate}")
    print()


def _run_in_cerf(bundle: str) -> None:
    cerf = resolve_cerf_exe()
    if cerf is None:
        print("ERROR: cerf.exe not found next to launcher.exe; cannot "
              "run-in-cerf.", file=sys.stderr)
        return
    try:
        subprocess.Popen([str(cerf), f"--device={bundle}"],
                         cwd=str(cerf.parent),
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
        print(f"Launching cerf.exe for {bundle}...")
    except OSError as exc:
        print(f"ERROR: failed to launch cerf.exe: {exc}", file=sys.stderr)


def _parse_package_ref(ref: str) -> Tuple[str, str]:
    """Split '<category>/<artifact>' (e.g. pdbs/pdbs,
    compact_flash_cards/jlime_cf.img) into its two components."""
    category, sep, key = ref.partition("/")
    if not sep or not category or not key:
        raise BundleError(
            f"package reference must be <category>/<artifact>, got: {ref!r}")
    return category, key


def _find_device(manager: BundleManager, name: str) -> DeviceBundle:
    for d in manager.list_devices():
        if d.name == name:
            return d
    raise BundleError(f"unknown bundle: {name}")


def _print_packages(device: DeviceBundle) -> None:
    if not device.packages:
        print(f"{device.name}: no additional packages")
        return
    for ps in device.packages:
        state = ps.state_label.lower()
        size = format_size(ps.remote.unpacked_size or ps.remote.archive_size)
        ref = f"{ps.remote.category}/{ps.remote.key}"
        label = package_category_label(ps.remote.category)
        print(f"{ref:48} {state:18} {size:>10}  {label}: {ps.remote.name}")


def _download_packages_all(manager: BundleManager,
                           cancel: threading.Event) -> None:
    for d in manager.list_devices():
        if not d.is_installed:
            continue
        for ps in d.packages:
            if ps.installed and not ps.has_update:
                continue
            print(f"Package {d.name} {ps.remote.category}/{ps.remote.key}...")
            manager.submit_install_package(
                d.name, ps.remote.category, ps.remote.key,
                _cli_progress, cancel).result()
            print()


def _install_device(manager: BundleManager, device: DeviceBundle,
                    cancel: threading.Event) -> str:
    """Download/update one device; returns the device directory name."""
    return manager.submit_install(device, _cli_progress, cancel).result()


def run_cli(devices_dir: Path, argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="launcher.exe sync")
    parser.add_argument("command", choices=(
        "list", "download", "update", "delete", "update-all",
        "packages", "download-package", "delete-package",
        "download-packages-all"))
    parser.add_argument("bundle", nargs="?")
    parser.add_argument("package", nargs="?",
                        help="package reference as <category>/<artifact>, "
                             "e.g. pdbs/pdbs")
    parser.add_argument("--run-in-cerf", action="store_true",
                        help="after a successful download/update, launch "
                             "cerf.exe --device=<bundle> and exit")
    args = parser.parse_args(argv)

    manager = BundleManager(devices_dir)
    try:
        manager.submit_refresh().result()
    except BundleError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    cancel = threading.Event()
    try:
        if args.command == "list":
            for d in manager.list_devices():
                state = "installed"
                if d.has_update:             state = "update available"
                elif d.has_cerf_json_update: state = "device pending update"
                elif not d.is_installed:     state = "available"
                elif d.is_user_device:       state = "user device"
                line = f"{d.name:32} {state:18}"
                if d.remote:
                    line += f" {d.remote.updated_at}"
                print(line)
            return 0
        if args.command == "update-all":
            devices = manager.list_devices()
            targets = [d for d in devices if d.has_update]
            cfg_targets = [d for d in devices if d.has_cerf_json_update]
            if targets:
                _print_rom_license_notice(f"{len(targets)} bundle(s)")
            for d in targets:
                _print_source_notice(d)
                print(f"Updating {d.name}...")
                _install_device(manager, d, cancel)
                print()
            for d in cfg_targets:
                print(f"Updating {d.name} config...")
                manager.submit_refresh_cerf_json(d.name).result()
            return 0
        if args.command == "download-packages-all":
            _download_packages_all(manager, cancel)
            return 0
        if not args.bundle:
            print(f"ERROR: {args.command} requires a bundle name", file=sys.stderr)
            return 1
        if args.command == "packages":
            _print_packages(_find_device(manager, args.bundle))
            return 0
        if args.command in ("download", "update"):
            _print_rom_license_notice(args.bundle)
            device = _find_device(manager, args.bundle)
            _print_source_notice(device)
            dir_name = _install_device(manager, device, cancel)
            if args.run_in_cerf:
                print()
                _run_in_cerf(dir_name)
        elif args.command == "delete":
            manager.submit_delete(args.bundle).result()
        elif args.command in ("download-package", "delete-package"):
            if not args.package:
                print(f"ERROR: {args.command} requires a package reference "
                      f"(<category>/<artifact>)", file=sys.stderr)
                return 1
            category, key = _parse_package_ref(args.package)
            if args.command == "download-package":
                _print_rom_license_notice(f"{args.bundle} {args.package}")
                _print_source_notice(_find_device(manager, args.bundle))
                manager.submit_install_package(
                    args.bundle, category, key, _cli_progress, cancel).result()
            else:
                manager.submit_delete_package(args.bundle, category, key).result()
        print()
        return 0
    except BundleError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        cancel.set()
        print("\nCancelled.", file=sys.stderr)
        return 130
    finally:
        manager.shutdown()
