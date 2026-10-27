#!/usr/bin/env python3
from __future__ import annotations

import json
import py_compile
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

CE_TOOLS = ("clarm.exe", "clthumb.exe", "clmips.exe", "clsh.exe", "link.exe", "lib.exe", "rc.exe")
CE_ARCHES = ("Armv4", "Armv4i", "Mipsii", "Mipsiv", "Sh3")
LINUX_PKGCONFIG = (("Qt6Widgets", "Qt 6 Widgets development files"),
                   ("Qt6Quick", "Qt 6 Quick development files"),
                   ("alsa", "ALSA development files"),
                   ("slirp", "libslirp development files"),
                   ("libzip", "libzip development files"),
                   ("nlohmann_json", "nlohmann-json development files"),
                   ("xcb", "XCB development files"),
                   ("xcb-randr", "XCB RandR development files"),
                   ("wayland-client", "Wayland client development files"))


class Checks:
    def __init__(self) -> None:
        self.results: List[Tuple[str, str, str]] = []
        self.failed = False

    def report(self, status: str, key: str, detail: str) -> None:
        self.results.append((status, key, detail))
        if status == "FAIL":
            self.failed = True


def git(*args: str, cwd: Path = ROOT) -> Tuple[int, str]:
    result = subprocess.run(["git", "-C", str(cwd)] + list(args), capture_output=True, text=True,
                            check=False)
    return result.returncode, result.stdout.strip()


def submodule_paths() -> List[str]:
    if not (ROOT / ".gitmodules").is_file():
        return []
    code, out = git("config", "-f", ".gitmodules", "--get-regexp", r"^submodule\..*\.path$")
    if code != 0:
        return []
    return [line.split(None, 1)[1] for line in out.splitlines() if len(line.split(None, 1)) == 2]


def core_libraries() -> List[str]:
    return [p for p in submodule_paths() if "/" not in p and (ROOT / p / ".git").exists()]


def missing_submodules() -> List[str]:
    return [p for p in submodule_paths()
            if not (ROOT / p).is_dir() or not any((ROOT / p).iterdir())]


def check_git_repo(c: Checks) -> bool:
    code, top = git("rev-parse", "--show-toplevel")
    if code != 0 or not top:
        c.report("FAIL", "git-repo", "not a git repository")
        return False
    c.report("OK", "git-repo", top)
    return True


def check_git_hooks(c: Checks) -> None:
    if not (ROOT / ".githooks" / "pre-commit").is_file():
        c.report("FAIL", "git-hooks", ".githooks/pre-commit is missing from the working tree")
        return
    _, path = git("config", "--get", "core.hooksPath")
    if path == ".githooks":
        c.report("OK", "git-hooks", "core.hooksPath = .githooks")
    elif not path:
        c.report("FAIL", "git-hooks", "core.hooksPath is unset -- git hooks never run in this clone")
    else:
        c.report("FAIL", "git-hooks", "core.hooksPath = {} (expected .githooks)".format(path))
    for lib in core_libraries():
        _, lib_path = git("config", "--get", "core.hooksPath", cwd=ROOT / lib)
        if lib_path == "../.githooks":
            c.report("OK", "git-hooks " + lib, "core.hooksPath = ../.githooks")
        else:
            c.report("FAIL", "git-hooks " + lib, "core.hooksPath = '{}' (expected ../.githooks) -- "
                     "commits in {} skip the pre-commit checks".format(lib_path, lib))


def check_stale_local_hooks(c: Checks) -> None:
    hooks = ROOT / ".git" / "hooks"
    stale = sorted(p.name for p in hooks.iterdir() if p.is_file() and p.suffix != ".sample") \
        if hooks.is_dir() else []
    if stale:
        c.report("WARN", "stale-local-hooks", "{} in .git/hooks (shadowed by core.hooksPath, delete "
                 "to avoid confusion)".format(", ".join(stale)))
    else:
        c.report("OK", "stale-local-hooks", "none")


def check_submodules(c: Checks) -> None:
    if not (ROOT / ".gitmodules").is_file():
        c.report("OK", "submodules", "none declared")
        return
    missing = missing_submodules()
    if missing:
        c.report("FAIL", "submodules", "not initialised: " + ", ".join(missing))
    else:
        c.report("OK", "submodules", "all initialised")


def check_python(c: Checks) -> None:
    c.report("OK", "python", "Python {} at {}".format(sys.version.split()[0], sys.executable))


def check_claude_hooks(c: Checks) -> None:
    settings = ROOT / ".claude" / "settings.json"
    if not settings.is_file():
        c.report("FAIL", "claude-hooks", ".claude/settings.json is missing")
        return
    raw = settings.read_text(encoding="utf-8-sig")
    try:
        json.loads(raw)
    except ValueError as exc:
        c.report("FAIL", "claude-hooks", ".claude/settings.json does not parse: {}".format(exc))
        return
    referenced = sorted(set(re.findall(r"\.claude/hooks/([A-Za-z0-9_]+\.py)", raw)))
    if not referenced:
        c.report("FAIL", "claude-hooks", "settings.json references no hook scripts")
        return
    hooks = ROOT / ".claude" / "hooks"
    missing = [h for h in referenced if not (hooks / h).is_file()]
    if missing:
        c.report("FAIL", "claude-hooks", "scripts referenced but absent: " + ", ".join(missing))
        return
    broken = []
    for h in referenced:
        try:
            py_compile.compile(str(hooks / h), doraise=True, cfile=None)
        except py_compile.PyCompileError:
            broken.append(h)
    if broken:
        c.report("FAIL", "claude-hooks", "scripts fail to compile: " + ", ".join(broken))
    else:
        c.report("OK", "claude-hooks", "{} hooks present and compiling".format(len(referenced)))


def check_windows_toolchain(c: Checks) -> None:
    import vcpkg_install
    import vs_toolchain
    if vcpkg_install.integration_props().is_file():
        c.report("OK", "vcpkg", "MSBuild integration present")
    else:
        c.report("FAIL", "vcpkg", "run 'vcpkg integrate install' from "
                 "'<VS install>\\VC\\vcpkg\\vcpkg.exe' -- build.py refuses to build without it")
    tc = vs_toolchain.find()
    if not tc.vswhere.is_file():
        c.report("FAIL", "msvc", "vswhere.exe not found -- install Visual Studio with the C++ "
                 "desktop workload")
        return
    if not tc.tools_version:
        c.report("FAIL", "msvc", "no usable MSVC toolset (>= {}, not 14.51.*) -- installed: {}"
                 .format(vs_toolchain.min_tools_version_text(), "; ".join(tc.installed)))
        return
    c.report("OK", "msvc", "{}, toolset {}".format(tc.instance.get("displayName", "?"),
                                                   tc.tools_version))
    if tc.cmake.is_file():
        c.report("OK", "cmake", str(tc.cmake))
    else:
        c.report("FAIL", "cmake", "absent -- install the 'C++ CMake tools for Windows' component "
                 "of {}".format(tc.instance.get("displayName", "Visual Studio")))
    import qt_windows
    prefix = qt_windows.prefix_dir(ROOT)
    if (prefix / qt_windows.STAMP_NAME).is_file():
        c.report("OK", "qt", str(prefix))
    else:
        c.report("WARN", "qt", "absent -- build.py builds Qt {} on its first run".format(
            qt_windows.QT_VERSION))


def check_ce_toolchain(c: Checks) -> None:
    import host_branch
    branch = host_branch.current()
    if not branch.builds_ce_apps:
        c.report("WARN", "ce-toolchain", "{} cannot build ce_apps/ -- build.py --ce-apps-from=<the "
                 "ce_apps directory of a Windows or Linux build> copies them".format(branch.name))
        return
    root = ROOT / "third_party" / "wince"
    if not root.is_dir():
        c.report("WARN", "ce-toolchain", "absent -- optional; needed only to build ce_apps/ (see "
                 "docs/ce_apps_setup.md)")
        return
    missing = [t for t in CE_TOOLS if not (root / "bin" / t).is_file()]
    for arch in CE_ARCHES:
        if not (root / "STANDARDSDK" / "Include" / arch).exists():
            missing.append("Include/" + arch)
        if not (root / "STANDARDSDK" / "Lib" / arch / "coredll.lib").exists():
            missing.append("Lib/{}/coredll.lib".format(arch))
    if missing:
        fix = ("re-run python tools/unpack_evc4.py --force" if sys.platform == "win32"
               else "copy third_party/wince from a Windows unpack, see docs/ce_apps_setup.md")
        c.report("FAIL", "ce-toolchain", "incomplete -- missing: {} ({})".format(
            ", ".join(missing), fix))
    else:
        c.report("OK", "ce-toolchain", ", ".join(CE_ARCHES))


def check_linux_toolchain(c: Checks) -> None:
    import build_posix
    for tool in build_posix.BUILD_TOOLS + ("pkg-config", "wine"):
        path = shutil.which(tool)
        c.report("OK" if path else "FAIL", tool, path or "absent from PATH")
    if shutil.which("pkg-config"):
        for module, what in LINUX_PKGCONFIG:
            found = subprocess.run(["pkg-config", "--modversion", module], capture_output=True,
                                   text=True, check=False)
            if found.returncode == 0:
                c.report("OK", module, found.stdout.strip())
            else:
                c.report("FAIL", module, "absent -- install the {}".format(what))


def check_macos_toolchain(c: Checks) -> None:
    import build_posix
    import homebrew_packages
    for tool in build_posix.BUILD_TOOLS + ("brew",):
        path = shutil.which(tool)
        c.report("OK" if path else "FAIL", tool, path or "absent from PATH")
    brew = shutil.which("brew")
    if brew is None:
        return
    for formula in homebrew_packages.BUILD_FORMULAE:
        found = subprocess.run([brew, "list", "--versions", formula], capture_output=True,
                               text=True, check=False)
        if found.returncode == 0 and found.stdout.strip():
            c.report("OK", "brew " + formula, found.stdout.strip())
        else:
            c.report("FAIL", "brew " + formula, "absent -- brew install {}".format(formula))


def run_checks(c: Checks) -> None:
    if not check_git_repo(c):
        return
    check_git_hooks(c)
    check_stale_local_hooks(c)
    check_submodules(c)
    check_python(c)
    check_claude_hooks(c)
    if sys.platform == "win32":
        check_windows_toolchain(c)
    elif sys.platform == "darwin":
        check_macos_toolchain(c)
    else:
        check_linux_toolchain(c)
    check_ce_toolchain(c)


def main(argv: List[str]) -> int:
    c = Checks()
    if "--check" in argv or "-Check" in argv:
        run_checks(c)
        for status, key, detail in c.results:
            print("{}\t{}\t{}".format(status, key, detail))
        return 1 if c.failed else 0

    print("\nCERF setup\n")
    if git("rev-parse", "--show-toplevel")[0] != 0:
        print("  FAIL  not a git repository -- run the setup from a cloned CERF tree")
        return 1
    git("config", "core.hooksPath", ".githooks")
    print("  set   core.hooksPath = .githooks")
    missing = missing_submodules()
    for path in missing:
        print("  init  submodule " + path)
        subprocess.run(["git", "-C", str(ROOT), "submodule", "update", "--init", "--recursive",
                        "--", path], check=False)
    if not missing:
        print("  skip  submodules already initialised (left untouched)")
    for lib in core_libraries():
        git("config", "core.hooksPath", "../.githooks", cwd=ROOT / lib)
        print("  set   {} core.hooksPath = ../.githooks".format(lib))
    print("")
    run_checks(c)
    for status, key, detail in c.results:
        print("  {:<5} {:<20} {}".format(status, key, detail))
    print("")
    if c.failed:
        print("Setup incomplete -- resolve the FAIL lines above, then re-run the setup.")
        return 1
    print("Ready. Build with build.py, launch the Claude dev environment with run_claude.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
