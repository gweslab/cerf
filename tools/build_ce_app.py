from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import host_branch

REPO_ROOT = Path(__file__).resolve().parent.parent
SDK = REPO_ROOT / "third_party" / "wince"
BIN = SDK / "bin"
CORE_INCLUDE = REPO_ROOT / "libCerfCore" / "include"
WINE_PREFIX = REPO_ROOT / "build" / "wineprefix"
NATIVE = sys.platform == "win32"


class CeBuildError(Exception):
    pass


def _arch_setup(arch: str, mips_isa: str):
    if arch == "mips":
        if mips_isa == "mips1":
            return ("clmips.exe", "MIPS",
                    ["-QMmips1", "-QMFPE", "-D_M_MRX000=3000", "-D_MIPS_", "-DR3000"],
                    "Mipsii", ["-DMIPS"], ["corelibc"])
        if mips_isa == "mips2":
            return ("clmips.exe", "MIPS",
                    ["-QMmips2", "-QMFPE", "-D_M_MRX000=4000", "-D_MIPS_", "-DR4000"],
                    "Mipsii", ["-DMIPS"], ["corelibc"])
        return ("clmips.exe", "MIPSFPU",
                ["-QMmips4", "-QMn32", "-QMFPE", "-D_MIPS64", "-D_MIPS_", "-DR4000"],
                "Mipsiv", ["-DMIPS"], ["corelibc"])
    if arch == "sh3":
        return ("clsh.exe", "SH3", ["-Qsh3", "-DSH3", "-D_SH3_"], "Sh3", ["-DSHx"], [])
    if arch == "arm_thumb":
        return ("clarm.exe", "THUMB", ["-QRarch4T", "-QRinterwork-return", "-DARMV4I"], "Armv4i",
                ["-DARM", "-D_ARM_"], [])
    return ("clarm.exe", "ARM", ["-QRarch4", "-DARMV4"], "Armv4", ["-DARM", "-D_ARM_"], [])


def _run(argv: Sequence[str], env: dict) -> int:
    command = [str(a) for a in argv]
    if not NATIVE:
        command.insert(0, "wine")
    return subprocess.run(command, env=env, check=False).returncode


def _arg(path) -> str:
    text = str(path)
    if NATIVE:
        return text
    if text.startswith("/"):
        return "Z:" + text.replace("/", "\\")
    return text.replace("/", "\\")


def _tool_env() -> dict:
    env = dict(os.environ)
    env["PATH"] = str(BIN) + os.pathsep + env.get("PATH", "")
    if not NATIVE:
        env["WINEPREFIX"] = str(WINE_PREFIX)
        env["WINEDEBUG"] = "-all"
        env["WINEDLLOVERRIDES"] = "mscoree=;mshtml="
    return env


def _mtime(path: Path) -> float:
    return path.stat().st_mtime


def _newest_header(dirs: Iterable[Path]) -> Optional[float]:
    newest = None
    for d in dirs:
        if not d.is_dir():
            continue
        for h in d.glob("*.h"):
            t = _mtime(h)
            if newest is None or t > newest:
                newest = t
    return newest


def _filtered_def(def_path: Path, local: Sequence[str], obj_dir: Path) -> Path:
    drop = {name.lower() for name in local}
    lines = def_path.read_text(encoding="ascii", errors="replace").splitlines()
    kept = [line for line in lines if line.strip().lower() not in drop]
    trimmed = obj_dir / "coredll_local_filtered.def"
    trimmed.write_bytes("".join(line + "\r\n" for line in kept).encode("ascii", errors="replace"))
    return trimmed.resolve()


def build(type: str, target: str, sources: Sequence[str] = ("main.c",), entry: str = "",
          libs: Sequence[str] = ("coredll",), link_extras: Sequence[str] = (),
          extra_includes: Sequence[str] = (), extra_lib_paths: Sequence[str] = (),
          forced_include: Sequence[str] = (), def_file: str = "", obj_dir: str = ".",
          arch: str = "arm", mips_isa: str = "mips4", subsystem_version: str = "3.00",
          wce_version: str = "300", rc: str = "", coredll_def: str = "",
          coredll_def_local: Sequence[str] = (), crt_libs: Sequence[str] = (),
          out_subdir: str = "") -> None:
    config = os.environ.get("CE_APPS_CONFIG") or "Release"
    mode = os.environ.get("CE_APPS_MODE") or "dev"
    dev_mode_flag = "0" if mode == "production" else "1"
    arch_sub = out_subdir or (mips_isa if arch == "mips" else arch)
    branch = host_branch.current()
    out_dir = host_branch.output_dir(REPO_ROOT, config, branch) / "ce_apps" / arch_sub
    out_dir.mkdir(parents=True, exist_ok=True)
    staged = out_dir / target

    prebuilt = os.environ.get("CE_APPS_FROM")
    if prebuilt:
        _copy_prebuilt(Path(prebuilt) / arch_sub / target, staged)
        return
    if not branch.builds_ce_apps:
        raise CeBuildError("ce_apps/ cannot be built on {}: the eMbedded Visual C++ 4.0 tools are "
                           "x86 Windows programs. Pass --ce-apps-from=<the ce_apps directory of "
                           "a Windows or Linux build>.".format(branch.name))
    if not BIN.is_dir():
        raise CeBuildError(
            "CE toolchain not found at {}\n\nBuilding ce_apps/ needs eMbedded Visual C++ 4.0. "
            "See docs/ce_apps_setup.md.\nVerify with: python tools/dev_setup.py --check".format(SDK))
    if not NATIVE and shutil.which("wine") is None:
        raise CeBuildError("wine not found on PATH. The eMbedded Visual C++ 4.0 tools are "
                           "Windows programs; install Wine to build ce_apps/ on this host.")

    cl_name, machine, arch_flags, sdk_sub, cpu_macros, implicit_libs = _arch_setup(arch, mips_isa)
    if crt_libs:
        implicit_libs = list(crt_libs)
    cl = BIN / cl_name
    link = BIN / "link.exe"
    resc = BIN / "rc.exe"
    sdk_inc = SDK / "STANDARDSDK" / "Include" / sdk_sub
    lib_dir = SDK / "STANDARDSDK" / "Lib" / sdk_sub
    for p in (cl, link, sdk_inc, lib_dir):
        if not p.exists():
            raise CeBuildError("CE toolchain incomplete: {} is missing (see docs/ce_apps_setup.md)"
                               .format(p))

    inc_dirs: List[Path] = [Path(i).resolve(strict=True) for i in extra_includes]
    inc_dirs += [sdk_inc, CORE_INCLUDE]

    env = _tool_env()

    if not entry:
        entry = "WinMain" if type == "exe" else "DllEntryPoint"

    objs_dir = Path(obj_dir)
    objs_dir.mkdir(parents=True, exist_ok=True)

    def_path: Optional[Path] = None
    if coredll_def:
        libtool = BIN / "lib.exe"
        if not libtool.is_file():
            raise CeBuildError("WCE lib tool missing: {}".format(libtool))
        def_path = Path(coredll_def).resolve(strict=True)
        if coredll_def_local:
            def_path = _filtered_def(def_path, coredll_def_local, objs_dir)
        core_lib = objs_dir / "coredll.lib"
        if _run([libtool, "/nologo", "/machine:" + machine, "/def:{}".format(_arg(def_path)),
                 "/out:{}".format(_arg(core_lib))], env) != 0:
            raise CeBuildError("by-name coredll import lib build failed: {}".format(coredll_def))

    mode_marker = objs_dir / ".build_mode"
    coredll_key = hashlib.sha256(def_path.read_bytes()).hexdigest().upper() if def_path else ""
    build_key = "{}-{}-{}-{}-{}-{}".format(mode, arch, mips_isa, wce_version, sdk_sub, coredll_key)
    cached = mode_marker.read_text(encoding="ascii").strip() if mode_marker.is_file() else ""
    if cached != build_key:
        for stale in list(objs_dir.glob("*.obj")) + list(objs_dir.glob("*.res")):
            if stale.is_file():
                stale.unlink()
        mode_marker.write_bytes(build_key.encode("ascii"))

    src_dirs = sorted({Path(s).resolve(strict=True).parent for s in sources})
    newest_hdr = _newest_header(list(src_dirs) +
                                [CORE_INCLUDE / "cerfcore" / "peripherals" / "cerf_virt"])

    objs: List[Path] = []
    for src in sources:
        obj = objs_dir / (Path(src).stem + ".obj")
        objs.append(obj)
        need = not obj.is_file()
        if not need:
            need = _mtime(Path(src)) > _mtime(obj)
        if not need and newest_hdr is not None:
            need = newest_hdr > _mtime(obj)
        if need:
            print("[CE] cl  {}".format(src), flush=True)
            argv = [cl, "/nologo", "/c", "/W3", "/WX", "/O2"] + arch_flags + cpu_macros + [
                "/DUNICODE", "/D_UNICODE", "/DUNDER_CE", "/D_WIN32_WCE=" + wce_version,
                "/DCERF_DEV_MODE=" + dev_mode_flag, "/Fo{}".format(_arg(obj))]
            for inc in inc_dirs:
                argv += ["/I", _arg(inc)]
            for fi in forced_include:
                argv += ["/FI", fi]
            argv.append(_arg(src))
            if _run(argv, env) != 0:
                raise CeBuildError("Compile failed: {}".format(src))

    res: Optional[Path] = None
    if rc:
        if not resc.is_file():
            raise CeBuildError("WCE resource compiler missing: {}".format(resc))
        rc_path = Path(rc).resolve(strict=True)
        res = objs_dir / (Path(rc).stem + ".res")
        if not res.is_file() or _mtime(rc_path) > _mtime(res):
            print("[CE] rc  {}".format(rc), flush=True)
            if _run([resc, "/r", "/fo", _arg(res), _arg(rc_path)], env) != 0:
                raise CeBuildError("Resource compile failed: {}".format(rc))

    need_link = not staged.is_file()
    if not need_link:
        staged_time = _mtime(staged)
        need_link = any(_mtime(o) > staged_time for o in objs) or \
            (res is not None and _mtime(res) > staged_time)

    if not need_link:
        print("[CE] {} up-to-date".format(target), flush=True)
        return

    print("[CE] link {} -> {}".format(target, staged), flush=True)
    argv = ["/nologo", "/subsystem:windowsce," + subsystem_version, "/entry:" + entry,
            "/machine:" + machine, "/nodefaultlib", "/libpath:{}".format(_arg(lib_dir)),
            "/out:{}".format(_arg(staged))]
    if coredll_def:
        argv = ["/libpath:{}".format(_arg(objs_dir))] + argv
    argv += ["/libpath:{}".format(_arg(Path(p).resolve(strict=True))) for p in extra_lib_paths]
    if type == "dll":
        argv += ["/dll", "/implib:" + _arg(Path(target).with_suffix(".lib"))]
        dll_def = def_file or str(Path(target).with_suffix(".def"))
        if Path(dll_def).exists():
            argv.append("/def:" + _arg(dll_def))
    argv += list(link_extras)
    argv += [_arg(o) for o in objs]
    if res is not None:
        argv.append(_arg(res))
    argv += [lib + ".lib" for lib in libs]
    argv += [lib + ".lib" for lib in implicit_libs]
    if _run([link] + argv, env) != 0:
        raise CeBuildError("Link failed: {}".format(target))
    print("[CE]      {} bytes".format(staged.stat().st_size), flush=True)


def _copy_prebuilt(source: Path, staged: Path) -> None:
    if not source.is_file():
        raise CeBuildError("{} is missing from the copied CE apps".format(source))
    if staged.is_file() and staged.read_bytes() == source.read_bytes():
        print("[CE] {} up-to-date".format(staged.name), flush=True)
        return
    shutil.copy2(str(source), str(staged))
    print("[CE] copy {} -> {}".format(source, staged), flush=True)


def run_app(app_dir: Path, variants: Sequence[dict]) -> int:
    os.chdir(app_dir)
    try:
        for variant in variants:
            build(**variant)
    except (CeBuildError, OSError) as exc:
        print("[CE] FAILED! {}".format(exc), flush=True)
        return 1
    return 0
