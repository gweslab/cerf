# CERF - Windows CE Runtime Foundation

![Logo](logo.png)

Run original Windows CE ARM applications on modern desktop Windows.

CERF is an ARM CPU emulator and Win32 API compatibility layer that executes WinCE ARM binaries natively on x64 Windows. It includes a full ARMv5 instruction set interpreter (ARM + Thumb modes), a PE loader for WinCE executables, and a comprehensive Win32 API thunking layer that translates COREDLL calls to native desktop Win32 APIs.

## Usage

```
cerf.exe <path-to-wince-app.exe>
```

## Features

- ARMv5TE instruction set emulation (ARM and Thumb modes)
- WinCE PE loader with import resolution and relocation support
- Win32 API thunking: GDI, windowing, memory, system, dialogs, menus, input, resources
- Automatic ARM-to-native callback bridging (WndProc, DlgProc, TimerProc)
- 64-bit safe handle marshaling between emulated 32-bit code and native x64 APIs

## Building

Requires Visual Studio 2022 with C++ desktop development workload.

```
msbuild cerf.sln /p:Configuration=Release /p:Platform=x64
```

Output: `build/Release/x64/cerf.exe`

## Status

Early stage. Several WinCE applications run successfully (Solitaire, etc). Many Win32 APIs are stubbed or partially implemented. Contributions welcome.

## Downloads

[![build](https://github.com/dz333n/cerf/actions/workflows/build.yml/badge.svg)](https://github.com/dz333n/cerf/actions/workflows/build.yml)

## License

[MIT](LICENSE)
