#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List

import host_branch

ROOT = Path(__file__).resolve().parent.parent
BRANCH = host_branch.by_name(host_branch.WIN32_X86)
WPT_DIR = Path(r"C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit")
SOURCE_DIRS = ("libCerfEngine", "libCerfCore", "cerf-qt")


class ProfileError(Exception):
    pass


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def newer_sources(exe_time: float) -> List[Path]:
    found: List[Path] = []
    for name in SOURCE_DIRS:
        for path in (ROOT / name).rglob("*"):
            if path.suffix in (".cpp", ".h") and path.is_file() and path.stat().st_mtime > exe_time:
                found.append(path)
                if len(found) == 5:
                    return found
    return found


def log_append(log: Path, text: str) -> None:
    with open(str(log), "a", encoding="utf-8") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")


def tee(argv: List[str], out: Path, log: Path, env: dict) -> None:
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                            errors="replace", env=env, check=False)
    text = result.stdout + result.stderr
    out.write_text(text, encoding="utf-8")
    log_append(log, text)


def profile(args) -> int:
    if sys.platform != "win32":
        raise ProfileError("profile_cerf uses the Windows Performance Toolkit; it runs on Windows "
                           "only")
    if not is_admin():
        print("\nERROR: profile_cerf.py must run elevated.")
        print("  ETW CPU sampling uses the kernel profiler provider, which is admin-only.\n")
        print("  Fix: open a terminal as Administrator, then:")
        print("    cd <path-to-cerf-repo>")
        print("    python tools\\profile_cerf.py " + " ".join(sys.argv[1:]) + "\n")
        return 2

    exe_dir = host_branch.output_dir(ROOT, args.config, BRANCH)
    exe = exe_dir / BRANCH.frontend
    if not exe.is_file():
        raise ProfileError("{} not found at {}. Build first: python build.py".format(BRANCH.frontend, exe))
    exe_time = exe.stat().st_mtime
    newer = newer_sources(exe_time)
    if newer:
        print("\nERROR: {} is older than source files.".format(BRANCH.frontend))
        print("  exe:    {}  ({})".format(exe, datetime.fromtimestamp(exe_time)))
        print("  newer sources (first 5):")
        for path in newer:
            print("    {}  ({})".format(path, datetime.fromtimestamp(path.stat().st_mtime)))
        print("\n  Build first: python build.py")
        print("  Or pass --skip-stale-check to profile the current exe anyway.\n")
        if not args.skip_stale_check:
            return 3

    out_dir = Path(args.out_dir) if args.out_dir else \
        ROOT / "tmp" / "profile_{}".format(datetime.now().strftime("%Y%m%d_%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)
    etl, profile_txt = out_dir / "cerf.etl", out_dir / "profile.txt"
    butterfly, log = out_dir / "butterfly.txt", out_dir / "collection.log"

    sym_cache = Path(os.environ.get("TEMP", str(out_dir))) / "cerf_symcache"
    sym_cache.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["_NT_SYMBOL_PATH"] = "{};SRV*{}*https://msdl.microsoft.com/download/symbols".format(
        exe_dir, sym_cache)
    env["_NT_SYMCACHE_PATH"] = str(sym_cache)

    wpr, xperf = WPT_DIR / "wpr.exe", WPT_DIR / "xperf.exe"
    if not wpr.is_file():
        raise ProfileError("WPT wpr.exe not found at {}. Install the Windows Performance Toolkit "
                           "(Windows SDK).".format(wpr))
    if not xperf.is_file():
        raise ProfileError("WPT xperf.exe not found at {}. Install the Windows Performance Toolkit."
                           .format(xperf))
    subprocess.run([str(wpr), "-cancel"], capture_output=True, check=False)

    log.write_text("=== profile_cerf.py ===\n", encoding="utf-8")
    for line in ("When:       {}".format(datetime.now().astimezone().isoformat()),
                 "Exe:        {}".format(exe), "CerfArgs:   {}".format(args.cerf_args),
                 "Duration:   {}s".format(args.duration_sec), "OutDir:     {}".format(out_dir),
                 "SymPath:    {}".format(env["_NT_SYMBOL_PATH"]), ""):
        log_append(log, line)

    print("[PROF] Starting CPU sampling (WPT wpr, CPU profile, system-trace mode)...", flush=True)
    started = subprocess.run([str(wpr), "-start", "CPU"], capture_output=True, text=True,
                             errors="replace", check=False)
    log_append(log, started.stdout + started.stderr)
    if started.returncode != 0:
        raise ProfileError("wpr -start CPU failed. See {}".format(log))

    proc = None
    try:
        print("[PROF] Launching cerf: {} {}".format(exe, args.cerf_args), flush=True)
        proc = subprocess.Popen([str(exe)] + shlex.split(args.cerf_args, posix=False),
                                cwd=str(exe_dir))
        print("[PROF] cerf PID={}. Sampling {}s...".format(proc.pid, args.duration_sec), flush=True)
        deadline = time.monotonic() + args.duration_sec
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.5)
        if proc.poll() is not None:
            print("[PROF] cerf exited on its own before deadline (exit={}).".format(proc.returncode))
        print("[PROF] Stopping trace (writing {})...".format(etl), flush=True)
        stopped = subprocess.run([str(wpr), "-stop", str(etl)], capture_output=True, text=True,
                                 errors="replace", check=False)
        log_append(log, stopped.stdout + stopped.stderr)
        if stopped.returncode != 0:
            raise ProfileError("wpr -stop failed. See {}".format(log))
        if not args.keep_running and proc.poll() is None:
            print("[PROF] Closing cerf (PID={})...".format(proc.pid), flush=True)
            proc.kill()
    except BaseException:
        subprocess.run([str(wpr), "-cancel"], capture_output=True, check=False)
        raise

    if not etl.is_file():
        raise ProfileError("No ETL file produced. See {}".format(log))
    print("[PROF] Trace captured: {}".format(etl))
    print("[PROF] Resolving symbols + extracting hotspots (first run fetches syms, slow)...",
          flush=True)
    log_append(log, "=== xperf profile -detail ===")
    tee([xperf, "-i", etl, "-symbols", "-tle", "-tti", "-a", "profile", "-detail"], profile_txt,
        log, env)
    log_append(log, "=== xperf stack -butterfly {} (cerf only) ===".format(args.min_hits))
    tee([xperf, "-i", etl, "-symbols", "-tle", "-tti", "-a", "stack", "-process", BRANCH.frontend,
         "-butterfly", args.min_hits], butterfly, log, env)

    print("\n=== Output ==========================================================")
    print("  ETL (open in WPA):  {}".format(etl))
    print("  Top functions:      {}".format(profile_txt))
    print("  Butterfly stacks:   {}".format(butterfly))
    print("  Full log:           {}".format(log))
    print("\n=== Next steps ======================================================")
    print('  GUI drill-down:    wpa.exe "{}"'.format(etl))
    print('  Re-extract top N:  xperf -i "{}" -symbols -a profile -detail'.format(etl))
    print('  Per-thread stacks: xperf -i "{}" -symbols -a stack -process {}\n'.format(etl, BRANCH.frontend))
    return 0


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="CPU-profile {} with ETW sampling.".format(BRANCH.frontend))
    parser.add_argument("--duration-sec", type=int, default=60)
    parser.add_argument("--cerf-args", default="")
    parser.add_argument("--config", default="Release")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--min-hits", type=int, default=50)
    parser.add_argument("--skip-stale-check", action="store_true")
    try:
        return profile(parser.parse_args(argv))
    except ProfileError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
