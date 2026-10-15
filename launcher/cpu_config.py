from __future__ import annotations
from i18n import t, data_text
from database_text import record_key

import re
from typing import Dict, List, Optional

from board_database import (CPU_CONFIG_PARAMS, CPU_CONFIGS, SOC_FAMILIES,
                            SOCS, soc_family_of, soc_of)

TYPE_BOOLEAN = "boolean"
TYPE_INTEGER = "integer"
TYPE_HEX = "hex"
TYPE_ENUM = "enum"

AUTO = "auto"
CUSTOM_LABEL = 'common.custom'

_HEX_TEXT = re.compile(r"^0[xX][0-9a-fA-F]{1,8}$")
_DECIMAL_TEXT = re.compile(r"^[0-9]{1,10}$")
_PRESETS_BY_ID = {c["id"]: c for c in CPU_CONFIGS if isinstance(c.get("id"), str)}


def board_arch(board_id: object) -> Optional[str]:
    family = soc_family_of(board_id)
    arch = family.get("arch") if family else None
    return arch if isinstance(arch, str) else None


def params_for_arch(arch: Optional[str]) -> List[dict]:
    return [p for p in CPU_CONFIG_PARAMS if p.get("arch") == arch]


def _values_of(row: dict) -> dict:
    values = row.get("values")
    return values if isinstance(values, dict) else {}


def resolve_preset(row: dict) -> Dict[str, object]:
    parent = _PRESETS_BY_ID.get(row.get("inherits_cpu_config_id", ""))
    out = resolve_preset(parent) if parent else {}
    out.update(_values_of(row))
    return out


def _soc_arch(soc_id: object) -> Optional[str]:
    soc = SOCS.get(soc_id) if isinstance(soc_id, str) else None
    family = SOC_FAMILIES.get(soc.get("family_id", "")) if soc else None
    return family.get("arch") if family else None


def presets_for_arch(arch: Optional[str]) -> List[dict]:
    return [c for c in CPU_CONFIGS
            if isinstance(c.get("soc_id"), str) and _soc_arch(c["soc_id"]) == arch]


def preset_name(row: dict) -> str:
    soc = SOCS.get(row.get("soc_id", ""), {})
    return soc.get("name", row.get("soc_id", ""))


def board_preset(board_id: object) -> Optional[dict]:
    soc = soc_of(board_id)
    if soc is None:
        return None
    for row in CPU_CONFIGS:
        if row.get("soc_id") == soc.get("id"):
            return row
    return None


def board_defaults(board_id: object) -> Dict[str, object]:
    row = board_preset(board_id)
    return resolve_preset(row) if row else {}


def normalized(param: dict, value: object) -> object:
    if param.get("type") == TYPE_HEX and isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            return value
    return value


def value_label(param: dict, value: object) -> str:
    kind = param.get("type")
    if kind == TYPE_BOOLEAN:
        return t("common.enabled") if value else t("common.disabled")
    if kind == TYPE_ENUM:
        for option in param.get("enum_values", []):
            if option.get("id") == value:
                return data_text(record_key("cpu_config_params", param) +
                                 ".enum_values." + str(value), option.get("name", value))
        return str(value)
    if kind == TYPE_HEX:
        number = normalized(param, value)
        return "0x{:08X}".format(number) if isinstance(number, int) else str(value)
    return str(value)


def auto_label(text: str) -> str:
    return t('launcher.cpu_config.auto_text', text=text)


def param_value_label(param: dict, default: object,
                      override: Optional[object]) -> str:
    if override is None:
        return auto_label(value_label(param, default))
    return value_label(param, override)


def auto_preset_label(board_id: object) -> str:
    row = board_preset(board_id)
    return auto_label(preset_name(row)) if row else ""


def preset_label(board_id: object, overrides: Dict[str, object]) -> str:
    if not overrides:
        return auto_preset_label(board_id)
    match = matching_preset(board_arch(board_id),
                            effective(board_defaults(board_id), overrides))
    return preset_name(match) if match else t(CUSTOM_LABEL)


def available(board_id: object) -> bool:
    return board_preset(board_id) is not None


def parse_text(param: dict, text: str) -> Optional[object]:
    text = text.strip()
    if param.get("type") == TYPE_HEX:
        if not _HEX_TEXT.match(text):
            return None
        return "0x{:08X}".format(int(text, 16))
    if param.get("type") == TYPE_INTEGER:
        if not _DECIMAL_TEXT.match(text) or int(text) > 0xFFFFFFFF:
            return None
        return int(text)
    return None


def effective(defaults: Dict[str, object],
              overrides: Dict[str, object]) -> Dict[str, object]:
    out = dict(defaults)
    out.update(overrides)
    return out


def matching_preset(arch: Optional[str],
                    values: Dict[str, object]) -> Optional[dict]:
    params = params_for_arch(arch)
    for row in presets_for_arch(arch):
        resolved = resolve_preset(row)
        if all(normalized(p, resolved.get(p["id"])) ==
               normalized(p, values.get(p["id"])) for p in params):
            return row
    return None


def applicable_overrides(board_id: object,
                         overrides: object) -> Dict[str, object]:
    if not isinstance(overrides, dict):
        return {}
    ids = {p["id"] for p in params_for_arch(board_arch(board_id))}
    return {k: v for k, v in overrides.items() if k in ids}
