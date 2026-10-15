from __future__ import annotations
from i18n import t

from device_state import DeviceSource


def source_caption(source: DeviceSource) -> str:
    return t("launcher.device_source_text.contributed_by") if source.is_community_member else t("common.source")


def source_credit(source: DeviceSource) -> str:
    if source.is_community_member:
        return t('launcher.device_source_text.this_rom_bundle_was_contributed_by_name', name=source.name)
    return t('launcher.device_source_text.this_rom_bundle_was_preserved_and_provided', name=source.name)
