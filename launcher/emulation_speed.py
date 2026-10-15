from __future__ import annotations
from i18n import t

from typing import Optional, Union

THROTTLE_KEY = "throttle_multiplier"
CPU_RATE_KEY = "cpu_rate_multiplier"
MULTIPLIER_KEYS = (THROTTLE_KEY, CPU_RATE_KEY)
DEFAULT_MULTIPLIER = 1

Number = Union[int, float]

_STEPS = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, None, 1.5, 2, 3, 4, 5,
          10)
THROTTLE_PRESETS = (0,) + _STEPS
CPU_RATE_PRESETS = _STEPS


def model_multiplier(value: object) -> Optional[Number]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def model_choice(model: dict, key: str) -> Optional[Number]:
    value = model_multiplier(model.get(key))
    return None if value is None or value == DEFAULT_MULTIPLIER else value


def multiplier_label(value: Optional[Number]) -> str:
    if value is None:
        return t("launcher.cpu_config.auto_text", text=DEFAULT_MULTIPLIER)
    return "{:g}".format(value)
