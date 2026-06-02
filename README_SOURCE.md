# <img src="gweslab.png" width="24" height="24" /> **CE Runtime Foundation** v{version} pre-alpha

A universal Windows CE emulator: a virtual ARM hardware platform that boots real CE and Windows Mobile ROMs on modern Windows.

> [!WARNING]
> **Early stage.** There are some bugs and boards are just MVP implementations. Some boards lack proper clocks, timings, caches, etc. - take into account. Today this is rather proof-of-concept. Contributions are welcome!

> [!CAUTION]
> **You can't put own apps or data into ROMs.** We really have no any kind of shared storage with host today. This is next version's goal - we'll try to add shared storage with our guest additions driver.

> [!TIP]
> Our touch input is misbehaving in some devices/requires some additional effort. If your clicks do not register, try holding the left button and wiggling the cursor a bit. 

<p align="center">
  <img src="https://cerf.dz3n.net/promo1_02062026_1900.gif" alt="CERF — Windows CE virtual platform (part 1)" />
</p>
<p align="center">
  <img src="https://cerf.dz3n.net/promo2_02062026_1900.gif" alt="CERF — Windows CE virtual platform (part 2)" />
</p>

## Usage

The easiest way to run CERF is **`launcher.exe`** — a GUI app shipped next to `cerf.exe` that downloads publicly available ROM bundles and boots them. Pick a device from the list, tweak launch options (resolution, logging, network) if you want, click **Launch CERF**.

![launcher screenshot](docs/launcher.png)

For direct invocation without the launcher:

| Command                        | Action                                                       |
| ------------------------------ | ------------------------------------------------------------ |
| `cerf.exe `                    | Boot default device (ce5_smdk2410)                           |
| `cerf.exe --device=devemu_ce6` | Boot specific device                                         |
| `cerf.exe --log=ALL`           | Enable every log channel                                     |
| `cerf.exe --flush-outputs`     | Force-flush logs (avoid truncation on crash, extremely slow) |

Logs are written to `cerf.log` next to the executable. On a fatal crash, every other thread's register state and a top-of-stack snapshot is dumped to `cerf.crash.log` next to it through a lock-free emergency writer (no ucrt, no mutexes). Run `cerf.exe --help` for the full CLI.

> [!NOTE]
> **`cerf.log` is quiet by default** — only critical `CERF` / `CAUTION` lines are written, so logging never dominates the hot path. Pass `--log=ALL` (or a channel list, e.g. `--log=BOOT,JIT,MMU`) to turn channels on.

## <img src="gweslab.png" width="24" height="24" /> Guest Additions

> [!WARNING]
> **Experimental and unstable.** Guest Additions are opt-in (`--guest-additions`), off by default, and under active development. Expect per-device rendering glitches and reduced stability — some guest OSes behave better than others. For the most stable experience, boot without it and let the ROM use its own stock drivers.

Guest Additions inject **CERF-built modules into the guest ROM at load time**, replacing the matching stock modules with CERF equivalents that cooperate directly with the host. Pass `--guest-additions` (or tick the matching launcher option) to enable them.

**Today** the payload is a single component: a **universal CERF display driver** (`cerf_guest.dll`). It is a *real* Windows CE display driver — built from genuine CE driver sources against the CE 6 DDGPE/GPE libraries — that takes the place of the board's stock display driver. A compatibility-shim layer lets that one CE 6-based driver run **unmodified on every supported Windows CE generation** (CE 3 through CE 7, including Windows Mobile 5 / 6): it transforms driver-interface data shapes back and forth at the OS boundary so that the CE 6 driver always sees CE 6 shapes while the target OS always sees its own, and both stay happy.

What it can do today:

- **One universal graphics driver** across CE 3 / 5 / 6 / 7 and Windows Mobile 5 / 6.
- **Arbitrary screen resolution**, decoupled from the device's original panel, via `--screen-width` / `--screen-height` — including resolutions far larger than the real hardware ever shipped.
- **Host-accelerated blitting** over a virtual command channel — the guest driver routes blits to the host, which performs the full set (copy, fill, format-convert, ROP, transparency, alpha-blend, gradient) in native code. Some guests can still be slow.

> [!WARNING]
> **Touch breaks at non-native resolution.** The board's touch peripheral still uses the device's original input driver, which expects the original screen dimensions — so with guest additions enabled, touch will most likely be broken (and the device hard to use) at any resolution other than the panel's native one. Custom input is the next step in guest additions work.

Where it is headed (planned, not yet implemented):

- **Dynamic screen resize** at runtime — resize the host window and the guest follows.
- **Shared storage** — host folders mounted into the guest.
- **Drag-and-drop file copy** between host and guest.
- **Shared clipboard** between host and guest.

Unique things you can do with guest additions driver today:

- Boot grayscale ODO CE3 in 1080p resolution with full color
- Boot iPaq H36xx series Pocket PC 2000/2002 in 1080p resolution with full color
- Boot Windows CE6+ in 2K resolution with full color

## Supported boards

<table>
  <thead>
    <tr>
      <th>SoC</th>
      <th>Board / Device ID / OS</th>
      <th>Features</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><b>{i_chip} Intel SA-1110</b><br/><sub>StrongARM</sub></td>
      <td>
        {i_pda} <b>Compaq iPAQ H3600 Series</b><br/>
        {i_os_ppc2000} Pocket PC 2000 <code>ipaq_h3600_ppc2000</code><br/>
        {i_os_ppc2002} Pocket PC 2002 <code>ipaq_h3600_ppc2002</code>
      </td>
      <td>{i_display} {i_speaker} {i_stylus}</td>
    </tr>
    <tr>
      <td align="center"><b>{i_chip} Microsoft ODO (???)</b><br/><sub>ARM720T (1996 NDA board)</sub></td>
      <td>
        {i_pda} <b>ODO/Poseidon</b> (???)<br/>
        {i_os_old_ce} Windows CE 2.11 <code>odo_poseidon_ce2</code><br/>
        {i_os_old_ce} Windows CE 3 <code>odo_poseidon_ce3</code>
      </td>
      <td>{i_display} {i_speaker} {i_stylus} {i_keyboard}</td>
    </tr>
    <tr>
      <td align="center"><b>{i_chip} TI OMAP 3530</b><br/><sub>Cortex-A8</sub></td>
      <td>
        {i_pda} <b>OMAP 3530 EVM</b><br/>
        {i_os_ce} Windows CE 7 <code>omap_3530_evm_ce7</code>
      </td>
      <td>{i_display} {i_stylus}</td>
    </tr>
    <tr>
      <td align="center"><b>{i_chip} Freescale i.MX31L</b><br/><sub>ARM1136</sub></td>
      <td>
        {i_pda} <b>Zune 30</b> (Pyxis Keel)<br/>
        {i_os_zune} Windows CE 5 <code>zune_keel</code>
      </td>
      <td>{i_display} {i_keyboard}</td>
    </tr>
    <tr>
      <td rowspan="3" align="center"><b>{i_chip} Samsung S3C2410</b><br/><sub>ARM920T</sub></td>
      <td>
        {i_pda} <b>Device Emulator</b><br/>
        {i_os_ce} Windows CE 6 <code>devemu_ce6</code><br/>
        {i_os_ppc2002} Windows Mobile 5 <code>devemu_wm5</code><br/>
        {i_os_wm6} Windows Mobile 6 <code>devemu_wm6</code><br/>
        <p>...any many other WM5+/smartphone</p>
      </td>
      <td>{i_display} {i_speaker} {i_stylus} {i_keyboard} {i_internet}</td>
    </tr>
    <tr>
      <td>
        {i_pda} <b>Device Emulator (CE 4.2/5 branches)</b><br/>
        {i_os_ppc2002} WM 2003 SE <code>devemu_wm2003se</code><br/>
        {i_os_ce} Windows CE 5 <code>devemu_ce5</code><br/>
      </td>
      <td>{i_display} {i_speaker} {i_stylus} {i_keyboard}</td>
    </tr>
    <tr>
      <td>
        {i_pda} <b>PB SMDK 2410 Sample</b><br/>
        {i_os_ce} Windows CE 5 <code>smdk2410_sample_ce5</code>
      </td>
      <td>&mdash;</td>
    </tr>
  </tbody>
</table>

## How CERF runs ROM images? (NK.BIN, etc.)

Each device under `devices/<name>/` contains a Windows CE ROM image (`*.nb0` or `*.bin`).

Each device declares a `cerf.json` describing itself and (optionally) overriding board / network / rom defaults:

```json
{
  "meta": {
    "device_name": "Microsoft Device Emulator (Windows Mobile 5 Pocket PC)",
    "board_name": "Device Emulator",
    "soc_family": "Samsung S3C2410 (ARM920T)",
    "os": { "name": "Windows Mobile", "ver_major": 5, "ver_minor": 0 },
    "device_year": 2005
  },
  "board": {
    "configurable_screen_width": 800,
    "configurable_screen_height": 600
  },
  "rom": {
    "primary": "NK.bin",
    "extensions": "EXT.bin",
    "recovery": "Recovery.bin"
  }
}
```

`meta` is informational (device identification for the launcher / status displays — SoC and Board selection at runtime still come from BoardDetector heuristics on the ROM). `board` is only honoured by BSPs with a configurable screen resolution (today only Device Emulator boards). `rom` is only needed when a device ships more than one partition; single-ROM devices auto-detect the `*.nb0` / `*.bin`.

See [device_config.h](cerf/core/device_config.h) for the full schema.

To determine what is the board, CERF looks inside of ROM and performs heuristic search by module names or binary blobs.

## Building

Requires Visual Studio 2026 with the C++ desktop development workload.

> [!NOTE]
> **First build on a fresh machine takes 1+ hour.** vcpkg compiles dependencies from source before CERF starts linking. This happens once per machine — subsequent builds reuse the cached `vcpkg_installed/` tree and finish in a few minutes. Do not interrupt the first build.

Initialise source/dependency submodules:

```
git submodule update --init --recursive
```

Build via the helper script:

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

Or invoke msbuild directly:

```
msbuild cerf.sln /p:Configuration=Release /p:Platform=Win32
```

## Third-party / Credits

- **[QEMU](https://www.qemu.org/)** 
- **[The Linux kernel](https://www.kernel.org/)** 
- **[nlohmann-json](https://github.com/nlohmann/json)**
- **[libslirp](https://gitlab.freedesktop.org/slirp/libslirp)** 
- JIT studied/inspired by Microsoft's Device Emulator (Shared Source Academic License, 2006)

## Roadmap

See [roadmap.md](docs/roadmap.md)

## Known Issues

- iPAQ H36xx series - hang after user interaction with device stopped for ~10 seconds (clock bugged?)
- iPAQ H36xx series - PCMCIA errors (not critical) - perhaps bad emulation/stubs
- DevEmu CE3 - PCMCIA errors
- OMAP 3530 EVM - XAML keyboard and IE are not rendering (blank white) and causing emulator to drop performance - do not open them
- Guest additions seem to destroy multi-XIP ROMs
- libslirp internet is extremely slow or doesn't work at all (CERF v1 bug)
- DevEmu WM2003SE - touch rarely works - reproducible on Device Emulator itself
- Keyboard seems to be broken on DevEmu WM ROMs
- Sound crippled on ODO and DevEmu - audio peripheral/ostimer problems

## Changelog

<table>
  <thead>
    <tr>
      <th>CERF Version</th>
      <th>Changes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>v3.0</td>
      <td>
        <ul>
          <li>GUEST ADDITIONS - injects own video driver into ROMs</li>
          <li>OMAP 3530 EVM board support (MVP)</li>
          <li>Zune 30 board support (MVP)</li>
          <li>Massive emulator UI overhaul</li>
          <li>ARMv5,v6,v7 VFP/NEON MVP support, massive JIT improvements</li>
          <li>Tons of bug fixes and improvements</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>v2.0</td>
      <td>
        <ul>
          <li>Initial release</li>
          <li>ARMv4 support</li>
          <li>DevEmu, iPAQ H3600, Microsoft ODO support (MVP)</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

## What happened to CERF v1?

> [!NOTE]
> CERF v1 reimplemented CE userspace + kernel in host C++ - coredll exports thunked, rehosted on Win32. It hit a hard ceiling: per-process host resources (GDI handles, atom tables, kernel handles) couldn't hold an entire guest OS, because v1 mocked CE at the user-API layer instead of below CE's own per-process isolation. v1 was overengineering hell that literally grew exponentially. v2 is a completely different project. v1's source lives at [cerf-v1-obsolete](https://github.com/gweslab/cerf-v1-obsolete).

## AI-generated code

> [!CAUTION]
> **DO NOT USE CERF CODEBASE AS REFERENCE FOR SoCs, BOARDS, PERIPHERALS** - AI WRITTEN CODE CAN'T BE TRUSTED!

100% generated by [Claude](https://claude.ai) via [Claude Code](https://docs.anthropic.com/en/docs/claude-code) — no human-written code. Not production-grade.

## Downloads

[![build](https://github.com/gweslab/cerf/actions/workflows/build.yml/badge.svg)](https://github.com/gweslab/cerf/actions/workflows/build.yml)
