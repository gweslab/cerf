from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
import yaml

from app_paths import install_root
from yaml_catalog import LANGUAGE_CODE, TranslationCatalog, read_catalog

_catalog: Optional[TranslationCatalog] = None


def catalog_directory() -> Path:
    import sys
    if getattr(sys, "frozen", False):
        directory = install_root() / "langs"
        if directory.is_dir():
            return directory
        embedded = getattr(sys, "_MEIPASS", None)
        if embedded:
            return Path(embedded) / "langs"
        return directory
    return Path(__file__).resolve().parent.parent / "langs"


def available_languages():
    directory = catalog_directory()
    result = []
    for path in sorted(directory.glob("*.yml")):
        if not LANGUAGE_CODE.fullmatch(path.stem):
            continue
        try:
            name, _ = read_catalog(path)
            result.append((path.stem, name))
        except (OSError, ValueError, yaml.YAMLError) as error:
            logging.warning("[I18N] %s: %s", path, error)
    return result


def set_language(language: str) -> None:
    global _catalog
    catalog = TranslationCatalog()
    for warning in catalog.load(catalog_directory(), language):
        logging.warning("[I18N] %s", warning)
    _catalog = catalog


def current_language() -> str:
    if _catalog is None:
        from app_settings import read_language
        set_language(read_language())
    return _catalog.language


def t(key: str, **arguments) -> str:
    current_language()
    return _catalog.text(key, **arguments)


def data_text(key: str, original: str) -> str:
    current_language()
    return _catalog.data_text(key, original)
