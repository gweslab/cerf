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
from tcl_data_filter import drop_unused_tcl_data
from PyInstaller.utils.hooks import collect_data_files

ASSETS       = REPO_ROOT / "cerf" / "assets"
ICON_PATH    = str(ASSETS / "cerf_setup.ico")
VERSION_PATH = str(REPO_ROOT / "cerf" / "version.h")

NAME = "cerf_installer"

UCRT_DIR = os.environ.get("CERF_LAUNCHER_UCRT", "")
UCRT_BINARIES = [(p, ".") for p in glob.glob(os.path.join(UCRT_DIR, "*.dll"))] \
                if UCRT_DIR else []

BAND_FILES = [(p, "assets") for p in
              sorted(glob.glob(str(ASSETS / "about_band_*.png")))]
DIALOG_ICONS = [(p, "assets/icons") for p in
                sorted(glob.glob(str(THIS_DIR / "assets" / "icons" / "cerf_*.png")))]

block_cipher = None

a = Analysis(
    [str(THIS_DIR / "cerf_installer.py")],
    pathex=[str(THIS_DIR)],
    binaries=UCRT_BINARIES,
    datas=[(ICON_PATH, "."), (VERSION_PATH, ".")] + BAND_FILES + DIALOG_ICONS
          + collect_data_files("sv_ttk"),
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_PATH,
    version=exe_version.build(VERSION_PATH, NAME + ".exe", NAME,
                              "Universal Windows CE emulator setup"),
)
