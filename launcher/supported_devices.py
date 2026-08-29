"""Local, developer-editable knowledge about device boards.

This list is the launcher's own opinion about which boards cerf.exe can
actually run, keyed on the ``board.id`` a bundle's cerf.json carries. Edit it
by hand when a new board lands in cerf.exe's BoardContext (see
``cerf/boards/board_context.h``) or when a board's quirks change.
compile_readme.py renders the same data into README.md's "Supported boards"
table, so the launcher and the README never drift apart.

Semantics (matched on ``board_id``):
  * ``supported: True``  -> cerf.exe runs this board; shown by default.
  * ``supported: False`` -> early WIP: cerf.exe has the board_id but it is
                            not user-ready; hidden by the "Hide unsupported"
                            filter and absent from the README.
  * a board.id with no entry here -> unsupported; hidden by "Hide unsupported".

``notes`` here EXTEND (do not replace) the per-ROM ``meta.notes`` shown in
the side panel. Use them for board-wide quirks that apply to every ROM on
the board.

``DYNAMIC_NOTES`` (bottom of this file) extends the side panel further with
predicate-gated additional notes: each entry's lambda runs against the
selected ROM's cerf.json metadata plus the board's feature map, so a note
can target e.g. "any networked board running Windows Mobile 4+". Add an
entry there when a note applies to a ROM-metadata predicate rather than one
whole board; grow ``RomContext`` with more metadata fields as new
predicates need them.

``features`` is an optional dict of capability -> bool the side panel shows
as icons. Three states per capability:
  * True  -> hardware present and working (colour icon)
  * False -> hardware present but unsupported in CERF (greyed icon)
  * key absent -> the board has no such hardware (icon hidden entirely)
Recognised keys are the first column of ``FEATURE_SPECS``.

``storage`` names the ROM input the board boots from - what the New-device
wizard asks the user for. Absent means ``STORAGE_FLAT`` (a flat storage
container: NK/XIP/NB0/etc, the CERF default). ``STORAGE_SEC_CONTAINER`` is
the Ford SYNC 2 factory-recovery ``.sec`` package.

``configurable_screen: True`` marks a board whose OAL accepts a configurable
stock-video screen size (cerf.exe --screen-width/height without guest
additions). Absent means fixed-LCD.

Supported entries also carry the board's silicon + OS coverage, shown in
the README table (and available to the launcher):
  * ``soc``               -> a ``Soc`` constant (family + microarchitecture).
  * ``operating_systems`` -> list of ``OperatingSystem`` constants the board
                             boots in this cerf version.
"""

from __future__ import annotations

from board_catalog_schema import (
    DynamicNote,
    HANDHELD_PC_2000,
    HANDHELD_PC_PRO,
    PALM_SIZE_PC,
    POCKET_PC_2000,
    POCKET_PC_2002,
    SOC_IMX31L,
    SOC_IMX51,
    SOC_ODO,
    SOC_OMAP3530,
    SOC_PR31500,
    SOC_PR31700,
    SOC_PXA255,
    SOC_PXA270,
    SOC_S3C2410,
    SOC_SA1100,
    SOC_SA1110,
    SOC_VR4102,
    SOC_VR4111,
    SOC_VR4121,
    SOC_VR4122,
    SOC_VR5500,
    STORAGE_SEC_CONTAINER,
    WINDOWS_CE_1,
    WINDOWS_CE_2,
    WINDOWS_CE_211,
    WINDOWS_CE_212,
    WINDOWS_CE_3,
    WINDOWS_CE_5,
    WINDOWS_CE_6,
    WINDOWS_CE_7,
    WINDOWS_CE_8,
    WINDOWS_CE_NET,
    WINDOWS_MOBILE_2003SE,
    WINDOWS_MOBILE_5,
    WINDOWS_MOBILE_6,
    ZUNE_OS_5,
    LINUX_BASED_OS,
)

AUDIO_ARTIFACTS = "Audio has artifacts/glitches"
GUEST_ADDITIONS_BREAK_ROM = "Do NOT use guest additions - they break the ROM"

BOARDS_INFORMATION = [
    {
        "name": "Device Emulator",
        "board_id": "devemu",
        "supported": True,
        "configurable_screen": True,
        "soc": SOC_S3C2410,
        "operating_systems": [
            WINDOWS_CE_6,
            WINDOWS_MOBILE_5,
            WINDOWS_MOBILE_6,
            WINDOWS_MOBILE_2003SE,
            WINDOWS_CE_5,
        ],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "keyboard": True,
            "network": True,
            "pcmcia": True,
            "battery": True,
            "suspend": True,
            "guest_additions": True,
        },
        "notes": [
            "Stock video: don't exceed 640x480 on Windows Mobile 6.5 or newer.",
            "Stock video: don't exceed 800x600 on any OS.",
        ],
    },
    {
        "name": "Falcon 4220",
        "board_id": "falcon_4220",
        "supported": True,
        "soc": SOC_PXA255,
        "operating_systems": [WINDOWS_CE_NET],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "keyboard": False,
            "network": True,
            "pcmcia": True,
            "battery": True,
            "suspend": True,
            "guest_additions": True,
        },
        "notes": [
            "CERF badly emulates stock video, it renders with artifacts. You can use it with Guest Additions "
            "insetad",
            AUDIO_ARTIFACTS,
        ],
    },
    {
        "name": "iPAQ H3100/H3600/H3700",
        "board_id": "ipaq_gen1",
        "supported": True,
        "soc": SOC_SA1110,
        "operating_systems": [POCKET_PC_2000, POCKET_PC_2002],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "keyboard": False,
            "network": True,
            "pcmcia": True,
            "battery": False,
            "suspend": True,
            "guest_additions": True,
            "mic": True,
        },
        "notes": [AUDIO_ARTIFACTS],
    },
    {
        "name": "HP Jornada 820",
        "board_id": "jornada_820",
        "supported": True,
        "soc": SOC_SA1100,
        "operating_systems": [HANDHELD_PC_PRO],
        "features": {
            "display": True,
            "sound": True,
            "keyboard": True,
            "pcmcia": True,
            "mouse": True,
            "network": True,
            "battery": True,
            "suspend": True,
            "guest_additions": True,
            "mic": False,
            "serial": False,
        },
    },
    {
        "name": "HP Jornada 720",
        "board_id": "jornada_720",
        "supported": True,
        "soc": SOC_SA1110,
        "operating_systems": [HANDHELD_PC_2000, LINUX_BASED_OS],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "keyboard": True,
            "network": True,
            "pcmcia": True,
            "battery": True,
            "suspend": True,
            "guest_additions": True,
            "mic": False,
            "serial": False,
        },
    },
    {
        "name": "Microsoft Windows CE Hardware Reference Platform",
        "board_id": "odo",
        "supported": True,
        "soc": SOC_ODO,
        "operating_systems": [WINDOWS_CE_211, WINDOWS_CE_3],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "keyboard": True,
            "battery": False,
            "guest_additions": True,
        },
        "notes": [
            AUDIO_ARTIFACTS,
            "Guest additions keyboard causes OS to HANG - switch to stock!",
        ],
    },
    {
        "name": "OMAP 3530 EVM",
        "board_id": "omap_3530_evm",
        "supported": True,
        "soc": SOC_OMAP3530,
        "operating_systems": [WINDOWS_CE_7, WINDOWS_CE_8],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "suspend": False,
            "guest_additions": True,
            "network": False,
        },
        "notes": [
            "ROMs with Compositor are slower",
        ],
    },
    {
        "name": "Zune 30",
        "board_id": "zune_30",
        "supported": True,
        "soc": SOC_IMX31L,
        "operating_systems": [ZUNE_OS_5],
        "features": {
            "display": True,
            "sound": True,
            "keyboard": True,
            "guest_additions": True,
            "battery": False,
        },
        "notes": [
            "CERF auto-generates HDD on first boot if there was no (hdd.img in device dir)",
            "Guest additions: You can open apps through shared storage + task manager, "
            "only extremely simple apps will run (like literally blank Win32 skeletons)",
        ],
    },
    {
        "name": "Siemens SIMpad SL4",
        "board_id": "simpad_sl4",
        "supported": True,
        "soc": SOC_SA1110,
        "operating_systems": [HANDHELD_PC_2000, WINDOWS_CE_NET],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "pcmcia": True,
            "network": True,
            "guest_additions": True,
            "battery": True,
            "mic": False,
        },
    },
    {
        "name": "NEC MobilePro 900",
        "board_id": "nec_mobilepro_900",
        "supported": True,
        "soc": SOC_PXA255,
        "operating_systems": [HANDHELD_PC_2000, WINDOWS_CE_NET],
        "features": {
            "display": True,
            "sound": True,
            "touch": True,
            "keyboard": True,
            "pcmcia": True,
            "network": True,
            "guest_additions": True,
            "battery": False,
            "mic": False,
            "suspend": False,
        },
        "notes": [
            "Emulated with serious lags / audio / visual issues",
        ],
    },
    {
        "name": "NEC MobilePro 700",
        "board_id": "nec_mobilepro_700",
        "supported": True,
        "soc": SOC_VR4102,
        "operating_systems": [WINDOWS_CE_2],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": True,
            "sound": False,
            "network": True,
            "pcmcia": True,
            "serial": True,
            "battery": False,
            "guest_additions": True,
            "suspend": True,
        },
    },
    {
        "name": "Casio Cassiopeia E-55",
        "board_id": "casio_cassiopeia_e55",
        "supported": True,
        "soc": SOC_VR4111,
        "operating_systems": [PALM_SIZE_PC],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": True,
            "guest_additions": True,
            "pcmcia": True,
            "serial": True,
            "network": True,
            "sound": False,
            "battery": False,
            "suspend": False,
        },
    },
    {
        "name": "Casio Cassiopeia EM-500",
        "board_id": "casio_cassiopeia_em500",
        "supported": True,
        "soc": SOC_VR4122,
        "operating_systems": [POCKET_PC_2000],
        "features": {
            "display": True,
            "touch": True,
            "sound": True,
            "guest_additions": True,
            "suspend": False,
            "keyboard": False,
            "mic": False,
            "network": False,
            "serial": False,
            "battery": False,
        },
    },
    {
        "name": "Casio Toricomail / Message-Cam / Pocket PostPet",
        "board_id": "casio_toricomail",
        "supported": True,
        "soc": SOC_VR4121,
        "operating_systems": [WINDOWS_CE_212],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": True,
            "sound": False,
            "network": False,
            "pcmcia": False,
            "mic": False,
        },
        "notes": [
            "Camera and microphone access crashes the emulator",
        ],
    },
    {
        "name": "NEC Rockhopper SG2_VR5500",
        "board_id": "nec_rockhopper",
        "supported": True,
        "soc": SOC_VR5500,
        "operating_systems": [WINDOWS_CE_6],
        "features": {
            "display": True,
            "mouse": True,
            "keyboard": True,
            "suspend": False,
            "sound": False,
            "guest_additions": True,
            "pcmcia": True,
            "network": True,
        },
        "notes": [
            "MIPS IV ROM is incompatible with MIPS II apps. Prefer using MIPS II ROM."
        ],
    },
    {
        "name": "Philips Nino 300",
        "board_id": "philips_nino_300",
        "supported": True,
        "soc": SOC_PR31700,
        "operating_systems": [PALM_SIZE_PC],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": True,
            "battery": True,
            "suspend": True,
            "guest_additions": True,
            "pcmcia": True,
            "sound": True,
            "serial": True,
        },
    },
    {
        "name": "Philips Velo 1",
        "board_id": "philips_velo_1",
        "supported": True,
        "soc": SOC_PR31500,
        "operating_systems": [WINDOWS_CE_1],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": True,
            "battery": True,
            "suspend": True,
            "guest_additions": False,
            "pcmcia": True,
            "network": True,
            "sound": True,
            "serial": True,
        },
    },
    {
        "name": "Sharp Mobilon HC-4100",
        "board_id": "sharp_mobilon_hc4100",
        "supported": True,
        "soc": SOC_PR31700,
        "operating_systems": [WINDOWS_CE_2],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": True,
            "battery": True,
            "suspend": False,
            "guest_additions": True,
            "pcmcia": True,
            "network": True,
            "sound": True,
            "serial": True,
        },
    },
    {
        "name": "Siemens P177",
        "board_id": "siemens_p177",
        "supported": True,
        "soc": SOC_S3C2410,
        "operating_systems": [WINDOWS_CE_5],
        "features": {
            "display": True,
            "touch": True,
            "network": False,
            "guest_additions": True,
        },
        "notes": [],
    },
    {
        "name": "SmartBook G138",
        "board_id": "smartbook_g138",
        "supported": True,
        "soc": SOC_SA1110,
        "operating_systems": [WINDOWS_CE_NET],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": True,
            "pcmcia": True,
            "network": True,
            "guest_additions": True,
            "battery": False,
            "mic": False,
            "suspend": True,
        },
    },
    {
        "name": "Ford SYNC 2",
        "board_id": "ford_sync_2",
        "supported": True,
        "storage": STORAGE_SEC_CONTAINER,
        "soc": SOC_IMX51,
        "operating_systems": [WINDOWS_CE_6],
        "features": {
            "display": True,
            "touch": True,
            "guest_additions": False,
            "sound": False,
        },
        "notes": [
            "THIS BOARD IS NOT EMULATED WELL AT ALL! All it can do is a boot to a glitching home screen and that's it",
            "On the first boot, guest flashes ~2GB NAND inside device dir from .sec file. It will take some time and x2 disk space. After first boot, you can remove .sec file if you are not going to re-flash.",
            "GPU has severe visual artifacts.",
            "A click on screen will likely crash CERF due to missing GPU implementation",
            "Guest additions are launching if re-run with complete nand.img, but somehow causing stock GPU crash",
        ],
    },
    {
        "name": "Symbol MK500",
        "board_id": "symbol_mk500",
        "supported": True,
        "soc": SOC_PXA270,
        "operating_systems": [WINDOWS_CE_5],
        "features": {
            "display": True,
            "touch": True,
            "keyboard": False,
            "sound": True,
            "network": False,
            "guest_additions": True,
        },
    },
]


DYNAMIC_NOTES = []
