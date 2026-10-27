from __future__ import annotations

from pathlib import Path

from header_defines import int_define, str_define

_ROOT = Path(__file__).resolve().parent.parent
_EXECUTABLE_NAMES = _ROOT / "cerf-qt" / "executable_names_text.h"
_INSTALL_ROOT = _ROOT / "cerf-qt" / "install_root_files_text.h"
_RESOURCE_PATHS = _ROOT / "cerf-qt" / "resource_paths_text.h"
_CORE_TEXT = _ROOT / "libCerfCore" / "include" / "cerfcore" / "core"

QML_SOURCE_DIR = Path("cerf-qt") / "cerfman" / "qml"
FRONTEND_NAME = str_define(_EXECUTABLE_NAMES, "CERF_FRONTEND_NAME")
PRODUCT_NAME = str_define(_CORE_TEXT / "product_name_text.h", "CERF_PRODUCT_NAME")
DB_JSON_NAME = str_define(_CORE_TEXT / "install_layout_text.h", "CERF_DB_JSON_NAME")
CE_APPS_DIR_NAME = str_define(_CORE_TEXT / "install_layout_text.h", "CERF_CE_APPS_DIR_NAME")
GLOBAL_CONFIG_NAME = str_define(_INSTALL_ROOT, "CERF_GLOBAL_CONFIG_NAME")
LICENSE_NAME = str_define(_INSTALL_ROOT, "CERF_LICENSE_NAME")
NOTICES_NAME = str_define(_INSTALL_ROOT, "CERF_NOTICES_NAME")
LICENSES_DIR_NAME = str_define(_INSTALL_ROOT, "CERF_LICENSES_DIR_NAME")
ASSET_ICONS_DIR = str_define(_RESOURCE_PATHS, "CERF_ASSET_ICONS_DIR")
BADGE_PREFIX = str_define(_RESOURCE_PATHS, "CERF_BADGE_PREFIX")
FONTS_DIR = str_define(_RESOURCE_PATHS, "CERF_FONTS_DIR")
FONT_SANS = str_define(_RESOURCE_PATHS, "CERF_FONT_SANS")
FONT_SANS_BOLD = str_define(_RESOURCE_PATHS, "CERF_FONT_SANS_BOLD")
CONTRIBUTORS_FILE = str_define(_RESOURCE_PATHS, "CERF_CONTRIBUTORS_FILE")
LOGO_ASSET = str_define(_RESOURCE_PATHS, "CERF_LOGO_ASSET")
LOGO_PX = int_define(_RESOURCE_PATHS, "CERF_LOGO_PX")
LOGO_PNG = f"{LOGO_ASSET}_{LOGO_PX}.png"
ERROR_ASSET = str_define(_RESOURCE_PATHS, "CERF_ERROR_ASSET")
ABOUT_BAND_ASSET = str_define(_RESOURCE_PATHS, "CERF_ABOUT_BAND_ASSET")
