import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path, PurePosixPath

HERE = Path(os.path.abspath(__file__)).parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "tools"))
import homebrew_packages
import host_branch
from macos_icns import IcnsError, make_icns

BUNDLED = REPO / "bundled"
CACHE = REPO / "references" / "python"
NAME = "launcher"
INSTALLER_NAME = "cerf_installer"

PY37_VERSION = "3.7.9"
PY37_SHA256 = "769bb7c74ad1df6d7d74071cc16a984ff6182e4016e11b8949b93db487977220"
PY37_URL = "https://www.python.org/ftp/python/{0}/python-{0}.exe".format(PY37_VERSION)
WINDOWS_PYINSTALLER = "5.13.2"
POSIX_PYINSTALLER = "6.22.3"

POSIX_FORWARDER = ('#!/bin/sh\n'
                   'here=$(dirname "$(readlink -f "$0")")\n'
                   'if [ ! -x "$here/{0}" ]; then\n'
                   '    echo "{0} could not be started. Re-download CERF from '
                   'https://cerf.cx/download" >&2\n'
                   '    exit 1\n'
                   'fi\n'
                   'exec "$here/{0}" "$@"\n')
ICON_SOURCE = REPO / "assets" / "cerf_1024.png"


class LauncherBuildError(Exception):
    pass


def say(text):
    print("[LAUNCHER] " + text, flush=True)


def run(argv, **kwargs):
    return subprocess.run([str(a) for a in argv], check=False, **kwargs).returncode


def sha256(path):
    digest = hashlib.sha256()
    with open(str(path), "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def windows_python():
    target = CACHE / "cpython-{}-x86".format(PY37_VERSION)
    python = target / "python.exe"
    if python.is_file():
        return python
    CACHE.mkdir(parents=True, exist_ok=True)
    installer = CACHE / "python-{}-x86.exe".format(PY37_VERSION)
    if not installer.is_file() or sha256(installer) != PY37_SHA256:
        say("Downloading CPython {} (x86, Vista-compatible) ...".format(PY37_VERSION))
        urllib.request.urlretrieve(PY37_URL, str(installer))
        got = sha256(installer)
        if got != PY37_SHA256:
            raise LauncherBuildError("Python archive SHA256 mismatch (got {}, want {})."
                                     .format(got, PY37_SHA256))
    say("Extracting CPython {} into references/python (per-user, not on PATH) ..."
        .format(PY37_VERSION))
    run([installer, "/quiet", "TargetDir={}".format(target), "InstallAllUsers=0", "PrependPath=0",
         "AssociateFiles=0", "Shortcuts=0", "Include_launcher=0", "InstallLauncherAllUsers=0",
         "Include_test=0", "Include_doc=0"], stdout=subprocess.DEVNULL)
    if not python.is_file():
        raise LauncherBuildError("python.exe not present at {} after extract.".format(python))
    return python


def ucrt_redist_dir():
    kits = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Windows Kits" / "10" / "Redist"
    if not kits.is_dir():
        return None
    for version in sorted((d for d in kits.iterdir() if d.is_dir()), key=lambda d: d.name,
                          reverse=True):
        ucrt = version / "ucrt" / "DLLs" / "x86"
        if ucrt.is_dir():
            return ucrt
    return None


def posix_base_python():
    if sys.platform != "darwin":
        return Path(sys.executable)
    brew = shutil.which("brew")
    if brew is None:
        raise LauncherBuildError("brew not found on PATH. Install Homebrew, then brew install {}."
                                 .format(homebrew_packages.TK_FORMULA))
    prefix = subprocess.run([brew, "--prefix", homebrew_packages.PYTHON_FORMULA],
                            capture_output=True, text=True, check=False).stdout.strip()
    python = Path(prefix) / "bin" / homebrew_packages.PYTHON_NAME
    if not prefix or not python.is_file():
        raise LauncherBuildError("{} is not installed. Run brew install {}."
                                 .format(homebrew_packages.PYTHON_FORMULA,
                                         homebrew_packages.TK_FORMULA))
    return python


def base_prefix(python):
    result = subprocess.run([str(python), "-c", "import sys; print(sys.base_prefix)"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def posix_python():
    base = posix_base_python()
    venv = CACHE / ("launcher-venv-macos" if sys.platform == "darwin" else "launcher-venv-linux")
    python = venv / "bin" / "python"
    if python.is_file() and base_prefix(python) != base_prefix(base):
        say("Recreating {} for {} ...".format(venv, base))
        shutil.rmtree(str(venv))
    if not python.is_file():
        say("Creating the launcher build environment in {} ...".format(venv))
        if run([base, "-m", "venv", venv]) != 0 or not python.is_file():
            raise LauncherBuildError("{} -m venv {} failed.".format(base, venv))
    if run([python, "-c", "import tkinter; tkinter.Tcl()"], stderr=subprocess.DEVNULL) != 0:
        raise LauncherBuildError("{} has no working tkinter. Install the Tk bindings of this "
                                 "Python (python3-tk, or {} on Homebrew)."
                                 .format(base, homebrew_packages.TK_FORMULA))
    return python


def ensure_package(python, module, requirement, version):
    probe = ("import importlib, sys\n"
             "importlib.import_module(sys.argv[1])\n"
             "try:\n"
             "    from importlib import metadata\n"
             "    print(metadata.version(sys.argv[2]))\n"
             "except ImportError:\n"
             "    import pkg_resources\n"
             "    print(pkg_resources.get_distribution(sys.argv[2]).version)\n")
    have = subprocess.run([str(python), "-c", probe, module, requirement], capture_output=True,
                          text=True, check=False)
    if have.returncode == 0 and have.stdout.strip() == version:
        return
    say("Installing {}=={} into {} ...".format(requirement, version, python))
    if run([python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
            "{}=={}".format(requirement, version)]) != 0:
        raise LauncherBuildError("pip install {}=={} failed.".format(requirement, version))


def pyinstaller(python, spec, env):
    code = run([python, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", HERE / "dist",
                "--workpath", HERE / "build", spec], cwd=str(HERE), env=env)
    if code != 0:
        raise LauncherBuildError("PyInstaller returned {} for {}".format(code, spec))


def install_onedir(built):
    if not built.is_dir():
        raise LauncherBuildError("Expected {} not produced.".format(built))
    BUNDLED.mkdir(parents=True, exist_ok=True)
    target = BUNDLED / built.name
    if target.exists():
        shutil.rmtree(str(target))
    shutil.copytree(str(built), str(target), symlinks=True)
    count = sum(1 for p in target.rglob("*") if p.is_file())
    say("OK: {} ({} files)".format(target, count))


def windows_stub(python, out_dir):
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        raise LauncherBuildError("vswhere.exe not found at {}.".format(vswhere))
    vs = subprocess.run([str(vswhere), "-latest", "-prerelease", "-property", "installationPath"],
                        capture_output=True, text=True, check=False).stdout.strip().splitlines()
    vcvars = Path(vs[0]) / "VC" / "Auxiliary" / "Build" / "vcvars32.bat" if vs else None
    if vcvars is None or not vcvars.is_file():
        raise LauncherBuildError("vcvars32.bat not found under {}.".format(vs[0] if vs else "?"))
    out_dir.mkdir(parents=True, exist_ok=True)
    assets = REPO / "assets"
    rc, res = out_dir / "launcher_stub.rc", out_dir / "launcher_stub.res"
    obj, out = out_dir / "launcher_stub.obj", out_dir / "launcher.exe"
    src = HERE / "stub" / "launcher_stub.c"
    script = ("import sys, exe_version, branding; open(sys.argv[1], 'w', encoding='utf-8').write("
              "exe_version.rc_script(sys.argv[2], 'launcher.exe', 'launcher', "
              "branding.PRODUCT_NAME, sys.argv[3:]))")
    code = run([python, "-c", script, rc,
                REPO / "libCerfFrontend" / "include" / "cerffrontend" / "version.h",
                assets / "cerf.ico", assets / "cerf_error.ico"], cwd=str(HERE))
    if code != 0:
        raise LauncherBuildError("stub resource script generation returned {}".format(code))
    cmd = ('"{}" >nul && rc /nologo /c65001 /fo "{}" "{}" && cl /nologo /O1 /GS- /W4 /c "{}" '
           '/Fo"{}" && link /nologo /NODEFAULTLIB /ENTRY:StubEntry /SUBSYSTEM:WINDOWS,6.00 '
           '/MANIFEST:EMBED /MANIFESTUAC:"level=\'asInvoker\' uiAccess=\'false\'" /OUT:"{}" "{}" '
           '"{}" kernel32.lib user32.lib').format(vcvars, res, rc, src, obj, out, obj, res)
    code = subprocess.run("cmd /s /c \"" + cmd + "\"", check=False).returncode
    if code != 0 or not out.is_file():
        raise LauncherBuildError("stub build returned {}".format(code))
    return out


def build_windows(config):
    python = windows_python()
    ucrt = ucrt_redist_dir()
    if ucrt is None:
        raise LauncherBuildError(
            "UCRT redist (Windows Kits\\10\\Redist\\<ver>\\ucrt\\DLLs\\x86) not found; "
            "launcher.exe would not run on a Vista box without KB2999226.")
    env = dict(os.environ)
    env["CERF_LAUNCHER_UCRT"] = str(ucrt)
    env["CERF_LAUNCHER_NAME"] = NAME
    ensure_package(python, "PyInstaller", "pyinstaller", WINDOWS_PYINSTALLER)
    clean()
    say("Building {}.exe ({})...".format(NAME, config))
    pyinstaller(python, "launcher.spec", env)
    if not (HERE / "dist" / NAME / (NAME + ".exe")).is_file():
        raise LauncherBuildError("Expected dist\\{0}\\{0}.exe not produced.".format(NAME))
    install_onedir(HERE / "dist" / NAME)
    stub = windows_stub(python, HERE / "build" / "stub")
    shutil.copy2(str(stub), str(BUNDLED / (NAME + ".exe")))
    say("OK: {} (stub, {} bytes)".format(BUNDLED / (NAME + ".exe"),
                                         (BUNDLED / (NAME + ".exe")).stat().st_size))
    say("Building {}.exe ({})...".format(INSTALLER_NAME, config))
    pyinstaller(python, "cerf_installer.spec", env)
    installer = HERE / "dist" / (INSTALLER_NAME + ".exe")
    if not installer.is_file():
        raise LauncherBuildError("Expected {} not produced.".format(installer))
    say("OK: {}".format(installer))
    say("Size: {} bytes".format(installer.stat().st_size))


def build_posix(config):
    launcher = PurePosixPath(host_branch.current().launcher)
    if launcher.name != NAME:
        raise LauncherBuildError("{} names no {} executable.".format(launcher, NAME))
    python = posix_python()
    env = dict(os.environ)
    env["CERF_LAUNCHER_NAME"] = NAME
    ensure_package(python, "PyInstaller", "pyinstaller", POSIX_PYINSTALLER)
    clean()
    if sys.platform == "darwin":
        icns = HERE / "build" / "cerf.icns"
        try:
            make_icns(ICON_SOURCE, icns)
        except IcnsError as exc:
            raise LauncherBuildError(str(exc)) from exc
        env["CERF_LAUNCHER_APP"] = launcher.parts[0]
        env["CERF_LAUNCHER_ICNS"] = str(icns)
    say("Building {} ({})...".format(launcher, config))
    pyinstaller(python, "launcher.spec", env)
    if not HERE.joinpath("dist", *launcher.parts).is_file():
        raise LauncherBuildError("Expected dist/{} not produced.".format(launcher))
    install_onedir(HERE / "dist" / launcher.parts[0])
    if launcher.parts[0] != NAME and (BUNDLED / NAME).is_dir():
        shutil.rmtree(str(BUNDLED / NAME))
    forwarder_name = host_branch.current().forwarder
    if forwarder_name is None:
        stale = BUNDLED / (NAME + ".sh")
        if stale.is_file():
            stale.unlink()
        say("OK: {}".format(BUNDLED / launcher.parts[0]))
        return
    forwarder = BUNDLED / forwarder_name
    forwarder.write_text(POSIX_FORWARDER.format(launcher), encoding="utf-8")
    forwarder.chmod(forwarder.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    say("OK: {} (forwarder)".format(forwarder))


def clean():
    for name in ("build", "dist"):
        path = HERE / name
        if path.exists():
            shutil.rmtree(str(path))


def main(argv):
    parser = argparse.ArgumentParser(description="Build the CERF launcher for this host.")
    parser.add_argument("--config", default="Release")
    args = parser.parse_args(argv)
    try:
        if sys.platform == "win32":
            build_windows(args.config)
        elif sys.platform.startswith("linux") or sys.platform == "darwin":
            build_posix(args.config)
        else:
            raise LauncherBuildError("no launcher build for {}".format(sys.platform))
    except (LauncherBuildError, OSError) as exc:
        say("FAILED! {}".format(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
