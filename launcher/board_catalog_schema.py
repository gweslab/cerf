"""Schema and vocabulary of the launcher's board-knowledge base: the
value types, operating-system / SoC constants, feature-icon specs, and
storage kinds that ``supported_devices.py`` authors its entries with,
plus the ``RomContext`` a ``DYNAMIC_NOTES`` predicate runs against."""
from __future__ import annotations

from typing import Callable, Dict, NamedTuple


class OperatingSystem(NamedTuple):
    name: str  # full display name


class Soc(NamedTuple):
    family: str  # e.g. "Intel SA-1110"
    arch: str  # e.g. "StrongARM"
    cpu: str  # CPU instruction-set family, e.g. "ARM" / "MIPS"


HANDHELD_PC_2000 = OperatingSystem("Handheld PC 2000")
POCKET_PC_2000 = OperatingSystem("Pocket PC 2000")
POCKET_PC_2002 = OperatingSystem("Pocket PC 2002")
WINDOWS_CE_1 = OperatingSystem("Windows CE 1.0")
WINDOWS_CE_2 = OperatingSystem("Windows CE 2.0")
PALM_SIZE_PC = OperatingSystem("Palm-size PC")
WINDOWS_CE_211 = OperatingSystem("Windows CE 2.11")
WINDOWS_CE_212 = OperatingSystem("Windows CE 2.12")
HANDHELD_PC_PRO = OperatingSystem("Handheld PC 3.0 Professional")
WINDOWS_CE_3 = OperatingSystem("Windows CE 3")
WINDOWS_CE_NET = OperatingSystem("Windows CE .NET")
WINDOWS_CE_5 = OperatingSystem("Windows CE 5")
WINDOWS_CE_6 = OperatingSystem("Windows Embedded CE 6")
WINDOWS_CE_7 = OperatingSystem("Windows Embedded Compact 7")
WINDOWS_MOBILE_2003SE = OperatingSystem("Windows Mobile 2003 SE")
WINDOWS_MOBILE_5 = OperatingSystem("Windows Mobile 5")
WINDOWS_MOBILE_6 = OperatingSystem("Windows Mobile 6")
ZUNE_OS_5 = OperatingSystem("Windows CE 5")
LINUX_BASED_OS = OperatingSystem("Linux")
WINDOWS_CE_8 = OperatingSystem("Windows Embedded Compact 2013")

SOC_SA1100 = Soc("Intel SA-1100", "StrongARM", "ARM")
SOC_SA1110 = Soc("Intel SA-1110", "StrongARM", "ARM")
SOC_PXA255 = Soc("Intel XScale PXA255", "ARMv5TE", "ARM")
SOC_PXA270 = Soc("Intel XScale PXA270", "ARMv5TE", "ARM")
SOC_ODO = Soc("ARM720T", "ARMv4T", "ARM")
SOC_OMAP3530 = Soc("TI OMAP 3530", "Cortex-A8", "ARM")
SOC_IMX31L = Soc("Freescale i.MX31L", "ARM1136", "ARM")
SOC_IMX51 = Soc("Freescale i.MX51", "Cortex-A8", "ARM")
SOC_S3C2410 = Soc("Samsung S3C2410", "ARM920T", "ARM")
SOC_VR5500 = Soc("NEC VR5500", "MIPS IV", "MIPS")
SOC_VR4102 = Soc("NEC VR4102", "MIPS III", "MIPS")
SOC_VR4121 = Soc("NEC VR4121", "MIPS III", "MIPS")
SOC_VR4122 = Soc("NEC VR4122", "MIPS III", "MIPS")
SOC_PR31700 = Soc("Philips PR31700", "MIPS I", "MIPS")
SOC_PR31500 = Soc("Philips PR31500", "MIPS I", "MIPS")

# Feature icons in display order, shared by the launcher side panel and
# compile_readme.py. (features key, icon stem, label). The stem names an SVG
# source under cerf/assets/icons_sources/; the launcher loads <stem>.png under
# assets/icons (emitted by tools/make_icons.py), the README/website use the SVG.
FEATURE_SPECS = [
    ("display", "display", "Display"),
    ("touch", "stylus", "Touch"),
    ("mouse", "cursor", "Mouse"),
    ("keyboard", "keyboard", "Keyboard"),
    ("suspend", "suspend", "Suspend / Resume"),
    ("guest_additions", "ga_autoresize", "Guest Additions"),
    ("sound", "speaker_active", "Sound"),
    ("mic", "microphone", "Microphone"),
    ("pcmcia", "pcmcia_enabled", "PCMCIA"),
    ("network", "internet", "Network"),
    ("battery", "battery", "Battery"),
    ("serial", "serial_com", "Serial Port"),
]

STORAGE_FLAT = "flat"
STORAGE_SEC_CONTAINER = "sec_container"


def sort_text(value: object) -> str:
    """Casefolded, whitespace-collapsed text for ordering/matching."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.casefold().split())


class RomContext(NamedTuple):
    """What a DYNAMIC_NOTES predicate gets to look at: the selected ROM's
    cerf.json metadata plus the board's feature map (same shape as
    ``board_features()``)."""

    os_name: str
    os_ver_major: int
    os_ver_minor: int
    board_id: str
    features: Dict[str, bool]
    cpu: str  # CPU instruction-set family, e.g. "ARM" / "MIPS"; "" when unknown

    def os_contains(self, fragment: str) -> bool:
        return sort_text(fragment) in sort_text(self.os_name)

    def board_is(self, board_id: str) -> bool:
        return self.board_id == board_id

    def cpu_is(self, name: str) -> bool:
        return sort_text(name) == sort_text(self.cpu)

    def has_feature(self, key: str) -> bool:
        # True only when present AND working; False = present-but-unsupported.
        return self.features.get(key) is True


class DynamicNote(NamedTuple):
    applies: Callable[[RomContext], bool]
    note: str
