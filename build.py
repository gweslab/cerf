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
import host_branch
from host_branch import WIN32_X86


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Build CERF for this host.")
    parser.add_argument("--config", "-Config", default="Release")
    parser.add_argument("--mode", "-Mode", choices=("dev", "production"), default="dev")
    parser.add_argument("--force-kill", "-ForceKill", action="store_true")
    parser.add_argument("--rebuild", "-Rebuild", action="store_true")
    parser.add_argument("--ce-apps-from", metavar="DIR",
                        help="copy ce_apps from the ce_apps directory of another build")
    args = parser.parse_args(argv)
    if args.config.lower() in ("d", "debug"):
        args.config = "Debug"
    elif args.config.lower() == "release":
        args.config = "Release"
    return args


def host_build(branch, args, heartbeat):
    if branch.name == WIN32_X86:
        import build_windows
        return build_windows, build_windows.WindowsBuild(ROOT, args.config, args.mode,
                                                         args.rebuild, heartbeat)
    import build_posix
    return build_posix, build_posix.PosixBuild(ROOT, args.config, args.mode, args.rebuild,
                                               heartbeat, branch)


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

    module, builder = host_build(branch, args, heartbeat)
    dev_flag = "0" if args.mode == "production" else "1"
    try:
        builder.discover()
        print("[BUILD] Mode: {} (CERF_DEV_MODE={})".format(args.mode, dev_flag), flush=True)
        report = build_common.BuildReport()
        heartbeat()
        build_common.build_launcher(ROOT, branch, args.config, args.rebuild, heartbeat, report)
        heartbeat()
        if not build_common.check_nested_pins(ROOT, args.mode == "production"):
            return 1
        if branch.name == WIN32_X86:
            builder.build_libraries()
            frontend_ok = builder.build_frontend()
        else:
            frontend_ok = builder.build()
    except module.BuildAbort as exc:
        print(str(exc), flush=True)
        return 1

    out = host_branch.output_dir(ROOT, args.config, branch)
    if frontend_ok:
        host_branch.stamp(out / "cerf.json", branch)
        print("[BUILD] {} stamped into {}".format(branch.name, out / "cerf.json"), flush=True)
        build_common.ship_notices(ROOT, out)
        report.ok()
    else:
        report.fail(branch.frontend)

    build_common.build_ce_apps(ROOT, args.config, args.mode, heartbeat, report, args.ce_apps_from)

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
        branch = host_branch.current()
    except host_branch.UnsupportedHost as exc:
        print("[BUILD] FAILED! {}".format(exc), flush=True)
        return 1

    if branch.name == WIN32_X86:
        import build_windows
        import gen_clangd
        gen_clangd.generate(ROOT)
        try:
            build_windows.check_vcpkg_integration()
        except build_windows.BuildAbort as exc:
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
