#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

import host_processes

GB = 1 << 30
ROOT_TAG = "%USE_PWD_TO_FIND_OUT_IF_YOU_READ_THIS%"
DOCS = ("CLAUDE.md", "README_SOURCE.md", "agent_docs/workflow.md",
        "agent_docs/workflow_examples.md", "agent_docs/subsystems.md",
        "agent_docs/boot_loaders.md", "agent_docs/rom_acceptance.md", "agent_docs/jit.md",
        "agent_docs/timers_clocks.md", "agent_docs/rules.md", "agent_docs/hibernation.md",
        "agent_docs/code_style.md", "agent_docs/debugging.md", "agent_docs/guest_additions.md",
        "agent_docs/deep_sleep.md", "agent_docs/cerfman.md",
        "agent_docs/psychological_support.md", "agent_docs/leds.md", "agent_docs/database.md",
        "agent_docs/submodules.md")

YELLOW, CYAN, GREEN, GRAY, RESET = "\x1b[33m", "\x1b[36m", "\x1b[32m", "\x1b[90m", "\x1b[0m"


def clear_screen() -> None:
    os.system("cls" if sys.platform == "win32" else "clear")


def parse_args(argv: List[str]):
    limits = {"memory": 4.2, "clangd": 1.5, "poll": 3}
    names = {"-MemoryLimitGB": "memory", "--memory-limit-gb": "memory",
             "-ClangdLimitGB": "clangd", "--clangd-limit-gb": "clangd",
             "-PollSeconds": "poll", "--poll-seconds": "poll"}
    claude_args: List[str] = []
    i = 0
    while i < len(argv):
        key = names.get(argv[i])
        if key is not None and i + 1 < len(argv):
            limits[key] = int(argv[i + 1]) if key == "poll" else float(argv[i + 1])
            i += 2
            continue
        claude_args.append(argv[i])
        i += 1
    return limits["memory"], limits["clangd"], int(limits["poll"]), claude_args


def first_run_gate() -> None:
    gate = ROOT / ".claude_gate"
    if gate.exists():
        return
    lines = [
        ("", CYAN + "  Welcome to the CERF Claude development environment" + RESET),
        ("", ""),
        ("", "  run_claude launches Claude Code with a custom system prompt that injects"),
        ("", "  the ENTIRE project documentation (CLAUDE.md + every agent_docs reference"),
        ("", "  page) into every agent, so each session starts fully briefed on the"),
        ("", "  project's rules, architecture, and subsystems."),
        ("", ""),
        (YELLOW, "  WARNING: Claude runs in skip-permissions mode. It can execute ABSOLUTELY"),
        (YELLOW, "  ANYTHING on this machine without asking: edit files, run shell commands,"),
        (YELLOW, "  delete data, hit the network."),
        ("", ""),
        (YELLOW, "  WARNING: this launcher polls for memory leaks. It will FORCE-KILL its own"),
        (YELLOW, "  Claude instance if it leaks past its limit, and it will FORCE-KILL ANY"),
        (YELLOW, "  clangd on this machine that leaks past its limit - not just ones it"),
        (YELLOW, "  started."),
        ("", ""),
        (GREEN, "  Tip: once inside, start by running  /cerf  to see the special skills this"),
        (GREEN, "  project provides (including /start-board-implementation to bring up a ROM)."),
        ("", ""),
        (CYAN, "  Press Enter to proceed (this message will never be shown again)."),
    ]
    print("")
    for color, text in lines:
        print(color + text + (RESET if color else ""))
    input()
    gate.touch()
    clear_screen()


def system_prompt() -> str:
    parts = []
    for index, rel in enumerate(DOCS):
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit("Mandatory document missing: {}".format(path))
        content = path.read_text(encoding="utf-8")
        parts.append(content if index == 0 else "{}:\n{}".format(rel, content))
    return "\n\n".join(parts).replace(ROOT_TAG, str(ROOT))


class Watchdogs:
    def __init__(self, limit_gb: float, clangd_gb: float, poll: int, log: Path) -> None:
        self.limit = int(limit_gb * GB)
        self.limit_gb = limit_gb
        self.clangd_limit = int(clangd_gb * GB)
        self.clangd_gb = clangd_gb
        self.poll = poll
        self.log_path = log
        self.stop = threading.Event()
        self.killed = False
        self.peak = 0
        self.target: Optional[int] = None
        self.existing = self._claude_pids()
        self.threads = [threading.Thread(target=self._watch_claude, daemon=True),
                        threading.Thread(target=self._watch_clangd, daemon=True)]

    @staticmethod
    def _named(name: str) -> Dict[int, str]:
        return {pid: n for pid, n in host_processes.list_processes().items()
                if n.lower() == name}

    def _claude_pids(self) -> set:
        return set(self._named("claude"))

    def log(self, text: str) -> None:
        try:
            with open(str(self.log_path), "a", encoding="utf-8") as handle:
                handle.write("[{}] {}\n".format(datetime.now().strftime("%H:%M:%S.%f")[:-3], text))
        except OSError:
            pass

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def finish(self) -> None:
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=5)

    def _watch_claude(self) -> None:
        self.log("----- watchdog start, limit={} GB, poll={}s -----".format(self.limit_gb,
                                                                           self.poll))
        self.log("preExisting claude pids: {}".format(",".join(str(p) for p in
                                                               sorted(self.existing))))
        deadline = time.monotonic() + 30
        while self.target is None and time.monotonic() < deadline:
            if self.stop.wait(0.3):
                return
            fresh = [pid for pid in self._claude_pids() if pid not in self.existing]
            if fresh:
                self.target = min(fresh, key=lambda p: host_processes.start_time(p) or 0)
        if self.target is None:
            self.log("TIMED OUT -- no new claude process appeared within 30s. Watchdog inactive.")
            return
        self.log("monitoring pid={} (private-bytes metric, threshold={})".format(self.target,
                                                                                self.limit))
        while not self.stop.wait(self.poll):
            used = host_processes.private_bytes(self.target)
            if used is None:
                self.log("process gone (exited normally or already killed)")
                break
            self.peak = max(self.peak, used)
            self.log("private={:,} bytes ({:.2f} GB)".format(used, used / float(GB)))
            if used > self.limit:
                self.log("OVER LIMIT -- killing pid={}".format(self.target))
                self.killed = True
                host_processes.kill(self.target)
                break
        self.log("----- watchdog exit -----")

    def _watch_clangd(self) -> None:
        self.log("----- clangd watchdog start, limit={} GB, poll={}s -----".format(self.clangd_gb,
                                                                                  self.poll))
        while not self.stop.wait(self.poll):
            for pid in self._named("clangd"):
                used = host_processes.private_bytes(pid)
                if used is not None and used > self.clangd_limit:
                    self.log("clangd OVER LIMIT -- killing pid={} private={:,} bytes ({:.2f} GB)"
                             .format(pid, used, used / float(GB)))
                    host_processes.kill(pid)


def main(argv: List[str]) -> int:
    limit_gb, clangd_gb, poll, claude_args = parse_args(argv)
    os.chdir(str(ROOT))
    clear_screen()
    os.environ["CLAUDE_CODE_DISABLE_BG_SHELL_PRESSURE_REAP"] = "1"
    first_run_gate()
    claude = shutil.which("claude")
    if claude is None:
        print("claude is not on PATH. Install Claude Code first.")
        return 1
    watchdog_log = Path(tempfile.gettempdir()) / "cerf_watchdog.log"
    while True:
        prompt_file = Path(tempfile.gettempdir()) / "cerf_sysprompt_{}.md".format(uuid.uuid4().hex)
        prompt_file.write_bytes(system_prompt().encode("utf-8"))
        dogs = Watchdogs(limit_gb, clangd_gb, poll, watchdog_log)
        dogs.start()
        try:
            subprocess.run([claude, "--effort", "xhigh", "--allow-dangerously-skip-permissions",
                            "--permission-mode", "bypassPermissions", "--system-prompt-file",
                            str(prompt_file)] + claude_args, check=False)
        except KeyboardInterrupt:
            pass
        finally:
            dogs.finish()
            try:
                prompt_file.unlink()
            except OSError:
                pass
        if not dogs.killed:
            return 0
        sys.stdout.write("\x1b[?1049l\x1b[?25h\x1b[0m")
        clear_screen()
        print("")
        print(YELLOW + "[run_claude] claude exceeded {} GB and was killed (peak private bytes: "
              "{:.2f} GB, pid {}).".format(limit_gb, dogs.peak / float(GB), dogs.target) + RESET)
        print(GRAY + "[run_claude] watchdog log: {}".format(watchdog_log) + RESET)
        reply = input("Restart claude? [Y/n] ").strip()
        if reply and not reply.lower().startswith("y"):
            return 0
        clear_screen()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
