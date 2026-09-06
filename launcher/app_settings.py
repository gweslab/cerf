from __future__ import annotations

import json

from bundle_repositories import config_path, load_config

DISCORD_RICH_PRESENCE_KEY = "discord_rich_presence"
UPDATE_CHANNEL_KEY = "update_channel"

CHANNEL_DISABLED = "disabled"
CHANNEL_STABLE = "stable"
CHANNEL_UNSTABLE = "unstable"
CHANNEL_DEFAULT = CHANNEL_STABLE
CHANNELS = (CHANNEL_DISABLED, CHANNEL_STABLE, CHANNEL_UNSTABLE)


def _update_config(mutate) -> None:
    path = config_path()
    obj = load_config(path)
    mutate(obj)
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def write_key(key: str, value) -> None:
    _update_config(lambda obj: obj.__setitem__(key, value))


def remove_key(key: str) -> None:
    _update_config(lambda obj: obj.pop(key, None))


def read_discord_rich_presence() -> bool:
    return load_config(config_path()).get(DISCORD_RICH_PRESENCE_KEY) is True


def write_discord_rich_presence(enabled: bool) -> None:
    write_key(DISCORD_RICH_PRESENCE_KEY, enabled)


def read_update_channel() -> str:
    value = load_config(config_path()).get(UPDATE_CHANNEL_KEY)
    return value if value in CHANNELS else CHANNEL_DEFAULT


def write_update_channel(channel: str) -> None:
    write_key(UPDATE_CHANNEL_KEY,
              channel if channel in CHANNELS else CHANNEL_DEFAULT)
