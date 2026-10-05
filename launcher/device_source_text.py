from __future__ import annotations

from device_state import DeviceSource


def source_caption(source: DeviceSource) -> str:
    return "Contributed by:" if source.is_community_member else "Source:"


def source_credit(source: DeviceSource) -> str:
    if source.is_community_member:
        return "This ROM bundle was contributed by {}.".format(source.name)
    return "This ROM bundle was preserved and provided by {}.".format(
        source.name)
