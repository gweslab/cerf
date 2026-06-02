# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import os

THIS_DIR = Path(os.path.abspath(SPEC)).parent
REPO_ROOT = THIS_DIR.parent
ICON_PATH    = str(REPO_ROOT / "cerf" / "assets" / "cerf.ico")
VERSION_PATH = str(REPO_ROOT / "cerf" / "version.h")

block_cipher = None

a = Analysis(
    [str(THIS_DIR / "launcher.py")],
    pathex=[str(THIS_DIR)],
    binaries=[],
    datas=[(ICON_PATH, "."), (VERSION_PATH, ".")],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=["numpy", "scipy", "pandas", "matplotlib"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="launcher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_PATH,
)
