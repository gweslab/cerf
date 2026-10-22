#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

import cerf_locks
import host_branch

EXIT_USAGE = 2
EXIT_MISSING = 3
EXIT_TIMEOUT = 124
EXIT_UNKNOWN = 125


def say(text: str) -> None:
    print("[RUNNER] " + text, flush=True)


def usage(slots: int, frontend: str) -> None:
    print("claude_cerf_runner - run {} under a time limit and a CERF run slot".format(frontend))
    print("")
    print("Usage:")
    print("  python3 claude_cerf_runner.py --timeout=SECONDS --log-file=PATH --device=NAME "
          "[{} args...]".format(frontend))
    print("")
    print("Mandatory:")
    print("  --timeout=SECONDS   Forwarded to {}. It stops the run and exits with code {}."
          .format(frontend, EXIT_TIMEOUT))
    print("                      If {} is still alive 10 s later, the runner stops it."
          .format(frontend))
    print("                      This replaces GNU timeout. Do not wrap this script in timeout.")
    print("                      An external kill leaves its .cerf_lock.N slot behind.")
    print("  --log-file=PATH     Forwarded to {}. It keeps the stock cerf.log intact."
          .format(frontend))
    print("                      msys and mixed-slash paths (/z/tmp/x.log, Z:/tmp/x.log) become "
          "Z:\\tmp\\x.log on Windows.")
    print("  --device=NAME       Forwarded to {}.".format(frontend))
    print("")
    print("The runner forwards every other argument to {} unchanged, and it adds --no-focus:"
          .format(frontend))
    print("CERF windows never take the foreground from another application.")
    print("It waits for .build_lock, and it holds one run slot (.cerf_lock.1 to .cerf_lock.{}) "
          "while {} runs.".format(slots, frontend))
    print("At most {} runs occur at the same time. When every slot is held, the next run waits "
          "for a free slot.".format(slots))
    print("")
    print("Exit codes: the exit code of {}, {} on timeout, {} on a bad argument,".format(
        frontend, EXIT_TIMEOUT, EXIT_USAGE))
    print("            {} when {} is absent, {} when the exit code is not available.".format(
        EXIT_MISSING, frontend, EXIT_UNKNOWN), flush=True)


def native_path(raw: str) -> Path:
    text = raw.strip().strip('"').strip("'")
    if sys.platform == "win32":
        m = re.match(r"^/cygdrive/([A-Za-z])/(.*)$", text) or re.match(r"^/([A-Za-z])/(.*)$", text)
        if m:
            text = m.group(1).upper() + ":/" + m.group(2)
        text = text.replace("/", "\\")
    path = Path(os.path.expanduser(text))
    if not path.is_absolute():
        path = ROOT / path
    return Path(os.path.abspath(str(path)))


def windows_arg(arg: str) -> str:
    if not re.search(r'[\s"]', arg):
        return arg
    out, backslashes = '"', 0
    for ch in arg:
        if ch == "\\":
            backslashes += 1
            continue
        if ch == '"':
            out += "\\" * (backslashes * 2 + 1) + '"'
        else:
            out += "\\" * backslashes + ch
        backslashes = 0
    return out + "\\" * (backslashes * 2) + '"'


def arg_line(args: List[str]) -> str:
    if sys.platform == "win32":
        return " ".join(windows_arg(a) for a in args)
    return " ".join(shlex.quote(a) for a in args)


def size_text(size: int) -> str:
    if size >= 1 << 20:
        return "{:,.1f} MB".format(size / float(1 << 20))
    if size >= 1 << 10:
        return "{:,.1f} KB".format(size / float(1 << 10))
    return "{} B".format(size)


def file_fact(label: str, path: Path, stale_before: Optional[float] = None,
              age_from_now: bool = False) -> None:
    if not path.exists():
        say("{:<14}: absent".format(label))
        return
    st = path.stat()
    note = ""
    if age_from_now:
        note = ", built {:,.1f} min ago".format((time.time() - st.st_mtime) / 60.0)
    elif stale_before is not None and st.st_mtime < stale_before:
        note = "  <-- older than this run"
    when = datetime.fromtimestamp(st.st_mtime)
    stamp = when.strftime("%H:%M:%S") if when.date() == datetime.now().date() \
        else when.strftime("%Y-%m-%d %H:%M:%S")
    say("{:<14}: {}, {}{}".format(label, size_text(st.st_size), stamp, note))


def tail_lines(path: Path, count: int) -> List[str]:
    block = 1 << 16
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        data = b""
        while pos > 0 and data.count(b"\n") <= count:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
    return data.decode("utf-8", errors="replace").splitlines()[-count:]


def os_exit_code(code: int) -> int:
    if code < 0 and sys.platform != "win32":
        return 128 - code
    if code > 0x7FFFFFFF:
        return code - (1 << 32)
    return code


def main(argv: List[str]) -> int:
    branch = host_branch.current()
    frontend = branch.frontend
    build_lock = cerf_locks.build_lock(ROOT, "RUNNER")
    run_locks = cerf_locks.run_locks(ROOT, "RUNNER")

    timeout_raw = log_raw = device = None
    forward: List[str] = []
    for arg in argv:
        if arg.startswith("--timeout="):
            timeout_raw = arg[len("--timeout="):]
        elif arg.startswith("--log-file="):
            log_raw = arg[len("--log-file="):]
        else:
            if arg.startswith("--device="):
                device = arg[len("--device="):]
            forward.append(arg)

    problems = []
    timeout = 0
    if not timeout_raw:
        problems.append("--timeout=SECONDS is mandatory")
    else:
        try:
            timeout = int(timeout_raw)
        except ValueError:
            timeout = 0
        if not 1 <= timeout <= 86400:
            problems.append("--timeout must be a whole number of seconds in 1..86400 (got '{}')"
                            .format(timeout_raw))
    if not log_raw:
        problems.append("--log-file=PATH is mandatory (it keeps the stock cerf.log intact)")
    if not device:
        problems.append("--device=NAME is mandatory")
    if problems:
        usage(len(run_locks), frontend)
        print("")
        for problem in problems:
            say("FAILED! " + problem)
        return EXIT_USAGE

    log_file = native_path(log_raw)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    forward += ["--log-file={}".format(log_file), "--timeout={}".format(timeout), "--no-focus"]
    emergency = timeout + 10

    exe_dir = host_branch.output_dir(ROOT, "Release", branch)
    exe = exe_dir.joinpath(*PurePosixPath(frontend).parts)
    note = " (converted from '{}')".format(log_raw) if str(log_file) != log_raw else ""
    say("{}, timeout {} s, emergency kill {} s, log {}{}".format(device, timeout, emergency,
                                                                log_file, note))

    while True:
        cerf_locks.wait(build_lock)
        slot = cerf_locks.enter_slot(run_locks)
        if cerf_locks.holder(build_lock) is None:
            break
        say("a build took .build_lock: releasing {} and waiting for the build".format(
            slot.path.name))
        cerf_locks.exit_lock(slot)
    try:
        say("run slot {}".format(slot.path.name))
        if not exe.is_file():
            say("FAILED! {} is absent at {}. Build it first.".format(frontend, exe))
            return EXIT_MISSING

        run_start = time.time()
        started = time.monotonic()
        proc = subprocess.Popen([str(exe)] + forward, cwd=str(exe_dir),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        say("{} PID {}: {}".format(frontend, proc.pid, arg_line(forward)))
        try:
            code = proc.wait(timeout=emergency)
            if code == EXIT_TIMEOUT:
                reason = "TIMEOUT: {} stopped the run at its own --timeout of {} s".format(
                    frontend, timeout)
            else:
                reason = "{} exited with code {}".format(frontend, code)
            code = os_exit_code(code)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            code = EXIT_TIMEOUT
            reason = ("EMERGENCY KILL: {0} did not exit at its own --timeout of {1} s. The runner "
                      "stopped it after {2} s. This is a CERF bug.".format(frontend, timeout,
                                                                           emergency))
        elapsed = time.monotonic() - started
        cerf_locks.update_stamp(slot)

        file_fact(frontend, exe, age_from_now=True)
        file_fact("live_state.png", exe_dir / "devices" / device / "live_state.png",
                  stale_before=run_start)
        file_fact("cerf.crash.log", exe_dir / "cerf.crash.log", stale_before=run_start)
        if not log_file.is_file():
            say("{:<14}: absent, {} wrote no log to {}".format("log file", frontend, log_file))
        else:
            say("{:<14}: {} ({}), last 3 lines:".format("log file", log_file,
                                                         size_text(log_file.stat().st_size)))
            for line in tail_lines(log_file, 3):
                print("  " + line)
        say("exit {} after {:.1f} s of {} s - {}".format(code, elapsed, timeout, reason))
        return code
    finally:
        cerf_locks.exit_slots(run_locks)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
