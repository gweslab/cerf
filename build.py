#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

import build_common
import cerf_locks
import frontend_build
import host_branch
from host_branch import ANDROID_AMD64, ANDROID_ARM64, WIN32_X86
from product_facts import GLOBAL_CONFIG_NAME

ANDROID_BRANCHES = {"arm64": ANDROID_ARM64, "amd64": ANDROID_AMD64}


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Build CERF for this host.")
    parser.add_argument("--config", "-Config", default="Release")
    parser.add_argument("--mode", "-Mode", choices=("dev", "production"), default="dev")
    parser.add_argument("--force-kill", "-ForceKill", action="store_true")
    parser.add_argument("--rebuild", "-Rebuild", action="store_true")
    parser.add_argument("--android", nargs="?", const="arm64", choices=sorted(ANDROID_BRANCHES),
                        help="build the Android package ({}) for this ABI (default arm64) instead of "
                             "the frontend of this host".format(host_branch.by_name(ANDROID_ARM64).frontend))
    parser.add_argument("--ce-apps-from", metavar="DIR",
                        help="copy ce_apps from the ce_apps directory of another build")
    args = parser.parse_args(argv)
    if args.config.lower() in ("d", "debug"):
        args.config = "Debug"
    elif args.config.lower() == "release":
        args.config = "Release"
    return args


def build_branch(args):
    if args.android:
        return host_branch.by_name(ANDROID_BRANCHES[args.android])
    return host_branch.current()


def host_build(branch, args, heartbeat):
    if branch.name in ANDROID_BRANCHES.values():
        import build_android
        return build_android.AndroidBuild(ROOT, args.config, args.mode, args.rebuild, heartbeat, branch)
    if branch.name == WIN32_X86:
        import build_windows
        return build_windows.WindowsBuild(ROOT, args.config, args.mode, args.rebuild, heartbeat, branch)
    import build_posix
    return build_posix.PosixBuild(ROOT, args.config, args.mode, args.rebuild, heartbeat, branch)


def run(args, branch, lock) -> int:
    def heartbeat():
        cerf_locks.update_stamp(lock)

    if not build_common.wait_for_blocking_processes(branch, args.force_kill, heartbeat):
        return 1
    heartbeat()

    started = time.monotonic()
    print("============================================================")
    print("[BUILD] Starting build: {} {}".format(args.config, branch.platform_dir))
    print("        Full rebuild might take 60+ minutes")
    print("============================================================", flush=True)

    builder = host_build(branch, args, heartbeat)
    dev_flag = "0" if args.mode == "production" else "1"
    try:
        builder.discover()
        print("[BUILD] Mode: {} (CERF_DEV_MODE={})".format(args.mode, dev_flag), flush=True)
        report = build_common.BuildReport()
        heartbeat()
        if not build_common.check_nested_pins(ROOT, args.mode == "production"):
            return 1
        build_common.build_ce_apps(ROOT, branch, args.config, args.mode, heartbeat, report,
                                   args.ce_apps_from)
        if branch.package_file and report.failed:
            print("[BUILD] FAILED! {} holds every CE app, and {} of them failed.".format(
                branch.frontend, report.failed), flush=True)
            return 1
        frontend_ok = builder.build()
    except frontend_build.BuildAbort as exc:
        print(str(exc), flush=True)
        return 1

    out = host_branch.output_dir(ROOT, args.config, branch)
    if frontend_ok:
        if not branch.package_file:
            host_branch.stamp(out / GLOBAL_CONFIG_NAME, branch)
            print("[BUILD] {} stamped into {}".format(branch.name, out / GLOBAL_CONFIG_NAME), flush=True)
            build_common.ship_notices(ROOT, out)
        report.ok()
    else:
        report.fail(branch.frontend)

    print("============================================================")
    if report.failed:
        print("[BUILD] Failed: {}".format(", ".join(report.failed_names)))
    elapsed = round((time.monotonic() - started) / 60.0, 1)
    print("[BUILD] Summary: {} succeeded, {} failed, elapsed {} minutes".format(
        report.succeeded, report.failed, elapsed), flush=True)
    return 1 if report.failed else 0


def main(argv) -> int:
    args = parse_args(argv)
    os.chdir(str(ROOT))
    try:
        branch = build_branch(args)
    except host_branch.UnsupportedHost as exc:
        print("[BUILD] FAILED! {}".format(exc), flush=True)
        return 1

    if branch.name == WIN32_X86:
        import build_windows
        import gen_clangd
        gen_clangd.generate(ROOT)
        try:
            build_windows.check_vcpkg_integration()
        except frontend_build.BuildAbort as exc:
            print(str(exc), flush=True)
            return 1

    lock = cerf_locks.build_lock(ROOT, "BUILD")
    cerf_locks.enter(lock)
    try:
        for run_lock in cerf_locks.run_locks(ROOT, "BUILD"):
            cerf_locks.wait(run_lock)
        return run(args, branch, lock)
    finally:
        cerf_locks.exit_lock(lock)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
