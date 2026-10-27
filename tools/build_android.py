from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

import android_openssl
import android_sdk
import build_report
import qt_android
import vcpkg_install
import verified_download
import vs_toolchain
from frontend_build import BuildAbort, FrontendBuild
from host_branch import output_dir
from product_facts import CE_APPS_DIR_NAME
from tool_process import prepend_path

SIGNING_VARIABLES = ("QT_ANDROID_KEYSTORE_PATH", "QT_ANDROID_KEYSTORE_ALIAS",
                     "QT_ANDROID_KEYSTORE_STORE_PASS", "QT_ANDROID_KEYSTORE_KEY_PASS")


def signing_configured() -> bool:
    return all(os.environ.get(name) for name in SIGNING_VARIABLES)


def _sdk_root() -> Path:
    for name in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(name)
        if value:
            return Path(value)
    raise BuildAbort("Set ANDROID_SDK_ROOT to an Android SDK with {}.".format(
        ", ".join(android_sdk.packages())))


def _ndk_revision(ndk: Path) -> Optional[str]:
    properties = ndk / "source.properties"
    if not properties.is_file():
        return None
    for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "Pkg.Revision":
            return value.strip()
    return None


def _tool(name: str) -> Path:
    found = shutil.which(name)
    if found is None:
        raise BuildAbort("{} not found on PATH.".format(name))
    return Path(found)


def _cmake_and_ninja() -> Tuple[Path, Path]:
    if os.name != "nt":
        return _tool("cmake"), _tool("ninja")
    toolchain = vs_toolchain.find()
    if toolchain.cmake is None or not toolchain.cmake.is_file():
        raise BuildAbort("CMake not found in Visual Studio. Install Visual Studio with the "
                         "C++ desktop workload and the 'C++ CMake tools for Windows' component.")
    if not toolchain.ninja.is_file():
        raise BuildAbort("Ninja not found at {}.".format(toolchain.ninja))
    return toolchain.cmake, toolchain.ninja


class AndroidBuild(FrontendBuild):
    device_traces = False
    sdk = Path()
    ndk = Path()
    java_home = Path()
    cmake = Path()
    ninja = Path()
    vcpkg_root = Path()

    def discover(self) -> None:
        if not qt_android.host_supported():
            raise BuildAbort("The Android build runs on a Windows or Linux host, not on {}."
                             .format(sys.platform))
        self.sdk = _sdk_root()
        self.ndk = self.sdk / "ndk" / android_sdk.NDK_VERSION
        revision = _ndk_revision(self.ndk)
        if revision != android_sdk.NDK_VERSION:
            raise BuildAbort("{} holds NDK {}, the build needs NDK {}.".format(
                self.ndk, revision, android_sdk.NDK_VERSION))
        java_home = os.environ.get("JAVA_HOME")
        java = "java.exe" if os.name == "nt" else "java"
        if not java_home or not (Path(java_home) / "bin" / java).is_file():
            raise BuildAbort("Set JAVA_HOME to a JDK 17 or newer.")
        self.java_home = Path(java_home)
        self.cmake, self.ninja = _cmake_and_ninja()
        try:
            self.vcpkg_root = vcpkg_install.vcpkg_root(self.branch.name)
        except (vcpkg_install.VcpkgError, OSError) as exc:
            raise BuildAbort(exc)
        print("[BUILD] Android SDK {}, NDK {}, JDK {}, cmake {}, ninja {}, vcpkg {}".format(
            self.sdk, android_sdk.NDK_VERSION, self.java_home, self.cmake, self.ninja, self.vcpkg_root),
            flush=True)

    def _environment(self) -> Dict[str, str]:
        env = prepend_path(dict(os.environ), self.cmake.parent, self.ninja.parent)
        env["ANDROID_NDK_HOME"] = str(self.ndk)
        env["ANDROID_SDK_ROOT"] = str(self.sdk)
        env["JAVA_HOME"] = str(self.java_home)
        return env

    def build(self) -> bool:
        env = self._environment()
        try:
            deps = vcpkg_install.install(self.root, self.vcpkg_root, vcpkg_install.TRIPLETS[self.branch.name], env,
                                         self.heartbeat)
            qt_target, qt_host = qt_android.ensure(self.root, self.branch.name, self.cmake, self.heartbeat)
            openssl = android_openssl.fetch(self.root, self.branch.name)
        except (vcpkg_install.VcpkgError, qt_android.QtFetchError, verified_download.DownloadError, OSError) as exc:
            raise BuildAbort(exc)
        resvg = self.resvg_options(env)
        out = output_dir(self.root, self.config, self.branch)
        build_dir = self.build_dir(self.config)
        self.clear_for_rebuild(build_dir)
        signed = signing_configured()
        self.configure(build_dir, [
            self.cmake, "-S", self.root, "-B", build_dir, "-G", "Ninja",
            "-DCMAKE_MAKE_PROGRAM={}".format(self.ninja),
            "-DCMAKE_BUILD_TYPE=" + self.config,
            "-DCMAKE_TOOLCHAIN_FILE={}".format(qt_target / "lib" / "cmake" / "Qt6" / "qt.toolchain.cmake"),
            "-DQT_HOST_PATH={}".format(qt_host),
            "-DANDROID_SDK_ROOT={}".format(self.sdk),
            "-DANDROID_NDK_ROOT={}".format(self.ndk),
            "-DANDROID_PLATFORM=" + android_sdk.platform_name(android_sdk.MIN_SDK),
            "-DANDROID_WEAK_API_DEFS=ON",
            "-DCMAKE_FIND_ROOT_PATH={}".format(deps),
            "-DCMAKE_PREFIX_PATH={}".format(deps),
            "-DCERFQT_ANDROID_CE_APPS_DIR={}".format(out / CE_APPS_DIR_NAME),
            "-DCERFQT_ANDROID_MIN_SDK={}".format(android_sdk.MIN_SDK),
            "-DCERFQT_ANDROID_TARGET_SDK={}".format(android_sdk.TARGET_SDK),
            "-DCERFQT_ANDROID_EXTRA_LIBS={}".format(";".join(path.as_posix() for path in openssl)),
            "-DCERFQT_HOST_BRANCH=" + self.branch.name,
            "-DQT_ANDROID_SIGN_APK=" + ("ON" if signed else "OFF")] + self.cmake_options() +
            self.compiler_cache_options() + resvg, env)
        if not self.compile([self.cmake, "--build", build_dir, "--target", "apk"], env):
            return False
        kind = self.config.lower()
        apk = build_dir / "cerf-qt" / "android-build" / "build" / "outputs" / "apk" / kind / \
            "android-build-{}-{}.apk".format(kind, "signed" if signed or kind == "debug" else "unsigned")
        return self._deliver(apk, out, signed or kind == "debug")

    def _deliver(self, apk: Path, out: Path, signed: bool) -> bool:
        if not build_report.built_file_present(self.branch.frontend, apk, "package"):
            return False
        out.mkdir(parents=True, exist_ok=True)
        target = out / self.branch.frontend
        shutil.copy2(str(apk), str(target))
        build_report.built_file(self.branch.frontend, target)
        if not signed:
            print("[BUILD] {} is unsigned. Set {} to sign it.".format(
                self.branch.frontend, ", ".join(SIGNING_VARIABLES)), flush=True)
        return True


if __name__ == "__main__":
    if sys.argv[1:] != ["--signed-output"]:
        raise SystemExit("usage: build_android.py --signed-output")
    print("signed={}".format("true" if signing_configured() else "false"))
