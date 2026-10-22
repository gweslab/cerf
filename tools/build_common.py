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

WINDOWS_BLOCKERS = ("cerf", "MSBuild", "cl", "link")
WAIT_BUDGET_SECONDS = 30 * 60
NESTED_PINS = (("libCerfEngine", "libservicelocator"), ("libCerfCore", "libCerfEngine"))
LAUNCHER_STAMP = ".launcher_timestamps"
LAUNCHER_EXTRA_INPUTS = ("assets/cerf.ico", "assets/cerf_error.ico",
                         "assets/cerf_setup.ico",
                         "libCerfFrontend/include/cerffrontend/version.h",
                         "libCerfFrontend/include/cerffrontend/integer_scales.h",
                         "cerf-qt/qt_evdev_vk.h", "cerf-qt/qt_mac_key_vk.h",
                         "cerf-qt/host_key_names.h", "tools/host_branch.py",
                         "tools/host_processes.py", "tools/macos_icns.py",
                         "assets/cerf_1024.png")
LAUNCHER_THEME_DIR = "external/sun_valley_theme"
NOTICE_FILES = ("LICENSE", "THIRD_PARTY_NOTICES.txt")
LICENSES_DIR = "licenses"


def ship_notices(root: Path, out: Path) -> None:
    for name in NOTICE_FILES:
        shutil.copy2(str(root / name), str(out / name))
    target = out / LICENSES_DIR
    if target.exists():
        shutil.rmtree(str(target))
    shutil.copytree(str(root / LICENSES_DIR), str(target))


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
        wanted = {n.lower() for n in WINDOWS_BLOCKERS}
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


def launcher_signature(root: Path) -> str:
    launcher = root / "launcher"
    inputs: List[Path] = []
    for path in launcher.rglob("*"):
        rel = path.relative_to(launcher).parts
        if not path.is_file() or rel[0] in ("build", "dist") or "__pycache__" in rel:
            continue
        if path.suffix == ".pyc" or path.name == LAUNCHER_STAMP:
            continue
        inputs.append(path)
    inputs += [root / rel for rel in LAUNCHER_EXTRA_INPUTS if (root / rel).is_file()]
    inputs += sorted((root / "assets").glob("about_band_*.png"))
    inputs += sorted(p for p in (root / LAUNCHER_THEME_DIR).rglob("*") if p.is_file())
    return "\n".join(sorted("{}|{}".format(p, p.stat().st_mtime_ns) for p in inputs))


def launcher_outputs(root: Path, branch: HostBranch) -> List[Path]:
    if branch.name == WIN32_X86:
        return [root / "bundled" / "launcher.exe", root / "bundled" / "launcher" / "launcher.exe",
                root / "launcher" / "dist" / "cerf_installer.exe"]
    return [root.joinpath("bundled", *PurePosixPath(branch.launcher).parts)]


def build_launcher(root: Path, branch: HostBranch, config: str, rebuild: bool,
                   heartbeat: Callable[[], None], report: BuildReport) -> None:
    script = root / "launcher" / "build.py"
    stamp = root / "launcher" / LAUNCHER_STAMP
    signature = launcher_signature(root)
    old = stamp.read_text(encoding="utf-8") if stamp.is_file() else ""
    if not rebuild and old == signature and all(p.is_file() for p in launcher_outputs(root, branch)):
        print("[LAUNCHER] up to date (no input changes) -- skipping", flush=True)
        report.ok()
        return
    print("[LAUNCHER]", flush=True)
    code = subprocess.run([sys.executable, str(script), "--config", config], check=False).returncode
    heartbeat()
    if code != 0:
        print("[LAUNCHER] build returned {}".format(code), flush=True)
        report.fail("launcher")
        return
    stamp.write_text(signature, encoding="utf-8")
    report.ok()


def build_ce_apps(root: Path, config: str, mode: str, heartbeat: Callable[[], None],
                  report: BuildReport, ce_apps_from: Optional[str] = None) -> None:
    env = dict(os.environ)
    env["CE_APPS_CONFIG"] = config
    env["CE_APPS_MODE"] = mode
    env.pop("CE_APPS_FROM", None)
    if ce_apps_from:
        env["CE_APPS_FROM"] = os.path.abspath(ce_apps_from)
    for app in sorted(p for p in (root / "ce_apps").iterdir() if p.is_dir()):
        script = app / "build.py"
        if not script.is_file():
            continue
        heartbeat()
        print("[CE] {}".format(app.name), flush=True)
        code = subprocess.run([sys.executable, str(script)], cwd=str(app), env=env,
                              check=False).returncode
        heartbeat()
        if code != 0:
            print("[CE] ce_apps/{} build returned {}".format(app.name, code), flush=True)
            report.fail("ce_apps/" + app.name)
        else:
            report.ok()
