# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import glob
import os
import sys

THIS_DIR = Path(os.path.abspath(SPEC)).parent
REPO_ROOT = THIS_DIR.parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))
import exe_version
from branding import PRODUCT_NAME
from tcl_data_filter import drop_unused_tcl_data

ASSETS       = REPO_ROOT / "assets"
ICON_PATH    = str(ASSETS / "cerf.ico")
UNINSTALL_ICON_PATH = str(ASSETS / "cerf_error.ico")
VERSION_PATH = str(REPO_ROOT / "libCerfFrontend" / "include" / "cerffrontend" / "version.h")
INTEGER_SCALES_PATH = str(REPO_ROOT / "libCerfFrontend" / "include" / "cerffrontend" /
                          "integer_scales.h")

NAME = os.environ.get("CERF_LAUNCHER_NAME", "launcher")

UCRT_DIR = os.environ.get("CERF_LAUNCHER_UCRT", "")
UCRT_BINARIES = [(p, ".") for p in glob.glob(os.path.join(UCRT_DIR, "*.dll"))] \
                if UCRT_DIR else []

BAND_FILES = [(p, "assets") for p in
              sorted(glob.glob(str(ASSETS / "about_band_*.png")))]

HOST_KEY_TABLES = [] if sys.platform == "win32" else [
    (str(REPO_ROOT / "cerf-qt" / ("qt_mac_key_vk.h" if sys.platform == "darwin"
                                  else "qt_evdev_vk.h")), "."),
    (str(REPO_ROOT / "cerf-qt" / "host_key_names.h"), "."),
]

block_cipher = None

a = Analysis(
    [str(THIS_DIR / "launcher.py")],
    pathex=[str(THIS_DIR), str(REPO_ROOT / "tools")],
    binaries=UCRT_BINARIES,
    datas=[(ICON_PATH, "."), (VERSION_PATH, "."), (INTEGER_SCALES_PATH, "."),
           (str(THIS_DIR / "assets" / "icons"), "assets/icons"),
           (str(THIS_DIR / "assets" / "contributors_generated.txt"),
            "assets"),
           (str(REPO_ROOT / "external" / "sun_valley_theme"), "sun_valley_theme")] + BAND_FILES + HOST_KEY_TABLES,
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=["numpy", "scipy", "pandas", "matplotlib"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
a.datas = drop_unused_tcl_data(a.datas)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[ICON_PATH, UNINSTALL_ICON_PATH] if sys.platform == "win32" else None,
    version=exe_version.build(VERSION_PATH, NAME + ".exe", NAME, PRODUCT_NAME)
    if sys.platform == "win32" else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name=NAME,
)

if sys.platform == "darwin":
    BUNDLE_VERSION = ".".join(str(n) for n in exe_version.version_tuple(VERSION_PATH)[:3])
    app = BUNDLE(
        coll,
        name=os.environ["CERF_LAUNCHER_APP"],
        icon=os.environ["CERF_LAUNCHER_ICNS"],
        bundle_identifier="cx.cerf.launcher",
        version=BUNDLE_VERSION,
        info_plist={"CFBundleVersion": BUNDLE_VERSION},
    )
