> [!WARNING]
> **This document covers development and contribution aspects**. Visit [cerf.cx](https://cerf.cx)
> for user-oriented documentation. This repository includes emulator frontends, website and other tools.

<img src="docs/github_band.svg" width="100%"/>
<div align="center">
  <b>Root repository - UIs and build tools</b><br/> 
  <a href="https://github.com/gweslab/libCerfEngine">libCerfEngine</a> - JIT repository;
    <a href="https://github.com/gweslab/libCerfCore">libCerfCore</a> - Emulator repository;
  <b><a href="https://cerf.cx">cerf.cx</a></b> - read more information about the project<br/>
</div><br/>

<div align="center">
  <a href="https://cerf.cx/discord"><img src="https://img.shields.io/badge/Discord-join%20the%20server-5865F2?logo=discord&amp;logoColor=white" alt="Discord"/></a> <a href="https://www.patreon.com/dz3n"><img src="https://img.shields.io/badge/Patreon-support-FF424D?logo=patreon&amp;logoColor=white" alt="Patreon"/></a>
</div>

<br/>

> [!WARNING]
> **Beta stage.** It is a hobby project, developed in spare time
> and can't be a called production-grade/exceptionally stable project.
> **Expect bugs, crashes, and breaking changes.** CERF stays beta permanently

> [!WARNING]
> [Non-commercial use only](https://cerf.cx/license-details)

## Downloads

Visit [the website](https://cerf.cx/download) to learn how to download a stable or an unstable build.

10.0 [![build](https://github.com/gweslab/cerf/actions/workflows/build.yml/badge.svg)](https://github.com/gweslab/cerf/actions/workflows/build.yml)

## [Contribution Guidelines](.github/CONTRIBUTING.md)

Please read [these](.github/CONTRIBUTING.md) if you are planning on contributing.

## Building

CERF builds on Windows, Linux and macOS with the same `build.py` script.

### Windows

Install modern Visual Studio with the C++ desktop development workload.

> [!NOTE]
> **The first build on a new machine takes more than one hour.** vcpkg compiles the dependencies from source, and `build.py` builds Qt into `third_party/qt/`. This occurs one time on each machine. Later builds use the cached trees and are complete in a few minutes. Do not stop the first build.

### Linux

Install the build packages. These are the Ubuntu 26.04 names:

```
sudo apt install git cmake ninja-build g++ pkg-config ccache wine clang patchelf curl zip unzip tar make perl bison flex libgl-dev libasound2-dev libxcb1-dev libxcb-randr0-dev libwayland-dev
```

Clone vcpkg and run `bootstrap-vcpkg.sh` in the clone. Set `VCPKG_ROOT` to the clone. The build downloads Qt into `third_party/qt/` and ships it with CERF.

### macOS

Install the Xcode Command Line Tools (`xcode-select --install`) and [Homebrew](https://brew.sh). Then install the build packages:

```
brew install cmake ninja pkgconf ccache qtbase qtsvg qtdeclarative libslirp libzip nlohmann-json
```

### All hosts

> [!CAUTION]
> Development environment might need additional configuration on your machine that this guide doesn't explain. If you find a bug there, or find a more universal approach - feel free to submit a pull request.

Configure the clone (one time on each machine), then build the entire project with a helper script. On Windows:

```
python tools/dev_setup.py
python build.py
```

On Linux and macOS:

```
python3 tools/dev_setup.py
python3 build.py
```

`tools/dev_setup.py --check` is a dry run. The setup will

- point git at tracked hooks
- report missing prerequisite

The build script will:

- wait for a parallel build (Claude Code-special feature for parallel agents work)
- install a pinned Rust toolchain into `third_party/rust` and build the resvg SVG renderer
- build the emulator itself (and will pick appropriate SDK/toolchain from your installations)
- build all the bundled Windows CE apps (at `ce_apps/`)

### Android

`python build.py --android` builds `build/<Config>/android-arm64/cerf.apk` on a Windows or x86-64 Linux host.

`python build.py --android=amd64` builds `build/<Config>/android-amd64/cerf.apk` for an x86_64 Android emulator. Install these first:

- the Android SDK with `platforms;android-36`, `build-tools;36.0.0` and `ndk;29.0.14206865`, and set `ANDROID_SDK_ROOT` to it
- a JDK 17 or newer, and set `JAVA_HOME` to it
- on Linux, a vcpkg checkout with `bootstrap-vcpkg.sh` run in it, and set `VCPKG_ROOT` to it

The build downloads Qt 6.12 for Android and for the host into `third_party/qt/`.

To sign the package, set `QT_ANDROID_KEYSTORE_PATH`, `QT_ANDROID_KEYSTORE_ALIAS`, `QT_ANDROID_KEYSTORE_STORE_PASS` and `QT_ANDROID_KEYSTORE_KEY_PASS`.

### Building the CE-side binaries (optional)

`ce_apps/` holds various Windows CE applications CERF is bundled with including the Guest Additions driver.

You don't need those if you are not working with Guest Additions. You may copy Guest Additions binaries from an artifact or skip them entirely. On x86-64 Linux the build runs these tools through Wine.

macOS and ARM64 Linux cannot run these tools. Give `build.py` the `ce_apps` directory of a Windows or x86-64 Linux build, for example from a CI artifact. The build then copies the binaries from that directory:

```
python3 build.py --ce-apps-from=<the ce_apps directory>
```

To build `ce_apps/`, install eMbedded Visual C++ 4.0 (a free Microsoft download from the
Microsoft archive). CERF includes a script that will unpack the installation (you dont want and probably can't install ancient tools)
and will place the build tools / SDK into appropriate directories.
See **[docs/ce_apps_setup.md](docs/ce_apps_setup.md)**.

`python tools/dev_setup.py --check` reports whether the CE toolchain is present.

### Website

This repository includes [cerf.cx](https://cerf.cx) source code at `docs/website`.

`python tools/build_site.py --serve` runs the website on your machine with live reload.

## AI Usage / Vibecode Notice

AI-assisted contributions are welcome. That's a nice thing to have in 2026 - you have access to tons of resources right in your pocket. Let me show generic use cases on this project:

- study emulators, study JIT, study assembly on various archs, study every piece that affects your code that you don't understand how it works yet
- learn and use AI to reverse engineer; use AI to reach for more correct architecture calls when you stall
- use AI to find projects/resources with compatible license to learn/borrow something complex
- use it to find manuals and papers for devices you target, SoCs/peripherals you target and to extract quotes from them
- use it to work with and explain complex data structures and non trivial algorithms
- use it to review your code and to criticize it
- the AI is an instrument to convert plain thoughts into a code - that's a replacement for typing code in order to get the same code you wanted but faster

The vibe code is banned. Please read [Contribution Guidelines](.github/CONTRIBUTING.md). Do not turn this into an AI slop. We put an effort here and we maintain a quality level.

Vibecoding non complex modules is fine but you will most likely violate the [Contribution Guidelines](.github/CONTRIBUTING.md) by producing shitcode.

## Claude Development Environment

The environment includes several controversial things you need to know before using it.

- Full project **documentation is injected** into a system prompt - this eats tokens
- The environment **kills** global `clangd.exe` and own `claude.exe` instances if they leak memory
- Thinking is set to _high_; **bypass permissions mode** is set
- Several own/3rd-party **skills** included
- Powerful hooks triggering when agent might do something bad to the codebase
- IDA MCP is ready to be installed at `tools\ida_server.py` and `tools\ida_claude.py`
- FS Read MCP is a workaround for `Read()` tool, useful for `/tracking restore` and massive text files (`tools\fs_read_mcp.py`)

The environment gives you the **`/implement-device`** skill. Run the skill and agent will start the new board bring-up on its own. You need experience - the skill won't do all the work instead of you. (it actually will do, and [that's the problem](#ai-usage--vibecode-notice))

Run the environment:

```
python run_claude.py
```

## [Supported Devices](https://cerf.cx/devices)

## Changelog

<table>
  <thead>
    <tr>
      <th>Version</th>
      <th>Release Date</th>
      <th>Changes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>v10.1</td>
      <td>TBA</td>
      <td>
        <p><b>📝 Changes</b><br/>
          No user affecting changes yet</p>
      </td>
    </tr>
    <tr>
      <td>v10.0</td>
      <td>21 Nov 2026</td>
      <td>
        <p><b>⚠️ Important</b><br/>
          ❗ Upgrade hangs - workaround: you need to wait 5 seconds during upgrade and let CERF kill the old process</p>
        <p><b>📱 Devices</b><br/>
          🆕 HP Jornada 680, HP 620LX support (thx @Gadgetoid/sh3-emu)<br/>
          🆕 HP 300LX, 320LX, 360LX family support (thx @Gadgetoid/sh3-emu)<br/>
          🆕 Casio Cassiopeia A11, A51; PA-2400U support (thx @Gadgetoid/sh3-emu)<br/>
          🆕 NEC MobilePro 450 support<br/>
          🆕 NEC Rockhopper: Improved CE.NET OAL support<br/>
          ✅ Casio Cassiopeia EM-500 family: Audio playback crash fixes, hardward buttons and HUD<br/>
          ✅ Sharp HC family: COM port issues fixed<br/>
          ✅ [Breaking] Symbol Mk500 family: NOR storage now handled properly. If you want to boot your saved device open Board Settings and set the old flash image into the new field<br/>
          ✅ Nino 300 family: Fixed touch lag/timing</p>
        <p><b>💿 Emulator</b><br/>
          🆕 SH3 guest CPU emulation<br/>
          🆕 RetroArch shaders support (librashader)<br/>
          🆕 Calibration helper - emulator performs calibration automatically<br/>
          🆕 Emulator crash now saves a state - you wont lose data on crash<br/>
          🆕 Automate your emulator with Python - https://cerf.cx/articles/automation<br/>
          ✅ PS/2 mouse lost double clicks on Android<br/>
          ✅ PS/2 mouse incorrect behaviour fixed<br/>
          ✅ Android&#x27;s HUD is now fully adaptive - saves your screen space<br/>
          ✅ Emulator is now large address aware, fixes some heavy boards halts on x64 systems<br/>
          ✅ Some global emulator parameters were overwritten each update</p>
        <p><b>🗂️ Devices Manager</b><br/>
          🆕 Import, export, clone your devices</p>
        <p><b>✨ Guest Additions</b><br/>
          ✅ Various crash fixes</p>
        <p><b>🌐 Website</b><br/>
          🆕 Live device database - https://cerf.cx/devices</p>
      </td>
    </tr>
    <tr>
      <td colspan="3"><b>Previous versions</b> - see the <a href="https://cerf.cx/changelog/">full changelog</a>.</td>
    </tr>
  </tbody>
</table>

---

CERF was known earlier as [WCECL](https://github.com/dz333n/wcecl) (2019)

[**CE Runtime Foundation License**](LICENSE) | [**Third-Party Notices**](THIRD_PARTY_NOTICES.txt)<br/>
**Copyright &copy; 2019-2026 [Yaroslav Kibysh](https://yaroslavkibysh.com)**
