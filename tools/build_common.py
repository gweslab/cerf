from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional

import host_processes
from host_branch import WIN32_X86, HostBranch
from product_facts import LICENSE_NAME, LICENSES_DIR_NAME, NOTICES_NAME
from tool_process import exit_code, failure_text

WINDOWS_TOOL_BLOCKERS = ("MSBuild", "cl", "link")
WAIT_BUDGET_SECONDS = 30 * 60
NESTED_PINS = (("libCerfEngine", "libservicelocator"), ("libCerfCore", "libCerfEngine"))


def ship_notices(root: Path, out: Path) -> None:
    for name in (LICENSE_NAME, NOTICES_NAME):
        shutil.copy2(str(root / name), str(out / name))
    target = out / LICENSES_DIR_NAME
    if target.exists():
        shutil.rmtree(str(target))
    shutil.copytree(str(root / LICENSES_DIR_NAME), str(target))


class BuildReport:
    def __init__(self) -> None:
        self.succeeded = 0
        self.failed = 0
        self.failed_names: List[str] = []

    def ok(self) -> None:
        self.succeeded += 1

    def fail(self, name: str) -> None:
        self.failed += 1
        self.failed_names.append(name)


def _blocking(branch: HostBranch) -> Dict[int, str]:
    if branch.name == WIN32_X86:
        wanted = {PurePosixPath(branch.frontend).stem.lower()} | {n.lower() for n in WINDOWS_TOOL_BLOCKERS}
    else:
        wanted = {PurePosixPath(branch.frontend).name.lower()}
    me = os.getpid()
    return {pid: name for pid, name in host_processes.list_processes().items()
            if name.lower() in wanted and pid != me}


def wait_for_blocking_processes(branch: HostBranch, force_kill: bool,
                                heartbeat: Callable[[], None]) -> bool:
    deadline = time.monotonic() + WAIT_BUDGET_SECONDS
    while True:
        procs = _blocking(branch)
        if not procs:
            return True
        if force_kill:
            for pid in procs:
                host_processes.kill(pid)
            time.sleep(5)
            return True
        names = ", ".join(sorted(set(procs.values())))
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            print("[BUILD] FAILED! The user OR other agent has been building/running CERF for "
                  "more than 30 minutes (processes: {}).".format(names))
            print("[BUILD] If you are 100% sure that this is yours stuck build, then re-run with: "
                  "build.py --force-kill")
            print("[BUILD] Otherwise, WAIT for the process to be closed and +~1 minute "
                  "(recommended). DONT CORRUPT SOMEONE'S WORK.", flush=True)
            return False
        print("[BUILD] Waiting for: {} ({} s budget remaining)...".format(names, remaining),
              flush=True)
        time.sleep(min(30, max(1, remaining)))
        heartbeat()


def _submodule_pin(repo: Path, path: str) -> Optional[str]:
    result = subprocess.run(["git", "-C", str(repo), "ls-files", "-s", "--", path],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    fields = result.stdout.split()
    return fields[1] if fields[0] == "160000" else None


def check_nested_pins(root: Path, production: bool) -> bool:
    for library, dependency in NESTED_PINS:
        root_pin = _submodule_pin(root, dependency)
        library_pin = _submodule_pin(root / library, dependency)
        if library_pin and library_pin != root_pin:
            if production:
                print("[BUILD] FAILED! {} pins {} {}, the root pins {}.".format(
                    library, dependency, library_pin, root_pin))
                print("[BUILD] Point both at the same commit before you build.", flush=True)
                return False
            print("[BUILD] WARNING: {} pins {} {}, the root pins {}. {} builds against the root "
                  "checkout.".format(library, dependency, library_pin, root_pin, library),
                  flush=True)
    return True


def build_ce_apps(root: Path, branch: HostBranch, config: str, mode: str,
                  heartbeat: Callable[[], None], report: BuildReport,
                  ce_apps_from: Optional[str] = None) -> None:
    env = dict(os.environ)
    env["CE_APPS_CONFIG"] = config
    env["CE_APPS_MODE"] = mode
    env["CE_APPS_HOST_BRANCH"] = branch.name
    env.pop("CE_APPS_FROM", None)
    if ce_apps_from:
        env["CE_APPS_FROM"] = os.path.abspath(ce_apps_from)
    for app in sorted(p for p in (root / "ce_apps").iterdir() if p.is_dir()):
        script = app / "build.py"
        if not script.is_file():
            continue
        heartbeat()
        print("[CE] {}".format(app.name), flush=True)
        code = exit_code([sys.executable, script], app, env)
        heartbeat()
        if code != 0:
            print("[CE] {}".format(failure_text("ce_apps/{} build".format(app.name), code)), flush=True)
            report.fail("ce_apps/" + app.name)
        else:
            report.ok()
