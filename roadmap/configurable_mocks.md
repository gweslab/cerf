# Configurable COREDLL Mocks — Roadmap

Things in COREDLL thunks that currently return real host values or are hardcoded,
and would benefit from being configurable via cerf.ini / CLI.

## Already Implemented

| What | INI key | CLI flag | Default |
|------|---------|----------|---------|
| Screen resolution | `screen_width`, `screen_height` | `--screen-width`, `--screen-height` | 800x480 |
| Fake screen toggle | `fake_screen_resolution` | `--fake-screen-resolution` | true |
| OS version | `os_major`, `os_minor`, `os_build` | `--os-major`, etc. | CE 5.0 build 1 |
| OS build date | `os_build_date` | `--os-build-date` | Jan 1 2008 |
| Physical RAM | `fake_total_phys` | `--fake-total-phys` | 0 (real host) |
| Device profile | `device` | `--device` | wince5 |

## Proposed

### GetDeviceCaps — display properties
- **Current**: Returns real desktop values for DPI, color depth, etc.
- **WinCE typical**: 96 DPI, 16-bit color (65536 colors), 240x320 or 480x640 resolution.
- **Why fake**: Apps may scale UI or choose bitmap resources based on DPI/color depth. Returning 32-bit 144 DPI desktop values breaks assumptions.
- **INI keys**: `screen_dpi=96`, `screen_color_depth=16`
- **Thunk**: `gdi_dc.cpp` GetDeviceCaps — LOGPIXELSX, LOGPIXELSY, BITSPIXEL, PLANES, HORZRES, VERTRES
- **Note**: BITSPIXEL is already overridden to 2 for commctrl bitmap selection. A configurable value would need to coexist with that override or replace it.

### GetPowerStatus — battery info
- **Current**: Stubbed, returns zero/unknown.
- **WinCE typical**: Battery level 0-100%, AC/battery power status, backup battery.
- **Why fake**: Battery meter apps (ResInfo Battery tab), power management UIs, apps that warn on low battery.
- **INI keys**: `battery_level=100`, `battery_charging=false`, `ac_power=true`
- **Thunk**: `system.cpp` GetSystemPowerStatusEx / GetSystemPowerStatusEx2
- **Struct**: SYSTEM_POWER_STATUS_EX — ACLineStatus, BatteryFlag, BatteryLifePercent, etc.

### GetStoreInformation — storage card info
- **Current**: Not implemented (would fail silently).
- **WinCE typical**: 32-256 MB storage, apps check free space before downloads/installs.
- **Why fake**: File manager apps, installers that check available storage.
- **INI keys**: `storage_total=134217728`, `storage_free=67108864`
- **Thunk**: `system.cpp` or new `storage.cpp`

### OEM info — device manufacturer/model
- **Current**: Not implemented.
- **WinCE typical**: SystemParametersInfoW(SPI_GETOEMINFO) returns OEM string, SPI_GETPLATFORMTYPE returns "PocketPC" or "HPC".
- **Why fake**: "About" dialogs, device identification, platform-specific code paths.
- **INI keys**: `oem_info=CERF Emulator`, `platform_type=PocketPC`
- **Thunk**: `system.cpp` SystemParametersInfoW cases for SPI_GETOEMINFO (0x0108), SPI_GETPLATFORMTYPE (0x0101)

### GetSystemInfo — CPU details
- **Current**: Returns hardcoded ARM processor type (4), real page size, 1 CPU.
- **WinCE typical**: Varies by device — ARM920T, XScale, ARM1136, etc.
- **Why fake**: Apps that display CPU info, or optimize for specific ARM variants.
- **INI keys**: `cpu_type=4`, `cpu_revision=0`, `cpu_count=1`
- **Thunk**: `system.cpp` GetSystemInfo

### Locale / language
- **Current**: Passes through to host locale APIs.
- **WinCE typical**: Device locale may differ from host (e.g. Japanese WinCE device on English desktop).
- **Why fake**: Apps with locale-dependent formatting, RTL layout, code page selection.
- **INI keys**: `locale=0x0409` (English US), `codepage=1252`
- **Thunk**: `system.cpp` GetLocaleInfoW, GetACP, GetUserDefaultLCID

### Time zone
- **Current**: Passes through to host GetTimeZoneInformation.
- **WinCE typical**: Embedded devices often in different timezone than development host.
- **Why fake**: Apps displaying local time, scheduling, timezone-aware calculations.
- **INI keys**: `timezone_bias=-540` (JST), `timezone_name=Tokyo Standard Time`
- **Thunk**: `system.cpp` GetTimeZoneInformation

### GetDeviceUniqueID / device identity
- **Current**: Not implemented.
- **WinCE typical**: Returns a device-specific hash, used for licensing and DRM.
- **Why fake**: Licensed apps that check device ID. Without it, they may refuse to run or enter trial mode.
- **INI keys**: `device_id=0123456789ABCDEF`
- **Thunk**: New thunk for ordinal or named export
