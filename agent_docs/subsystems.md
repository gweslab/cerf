# CERF Subsystems

The host-side subsystem set is small. CE-side binaries (kernel, OAL, drivers,
userspace) run unmodified as ARM code through the JIT — they are not host
subsystems. This page lists what CERF itself owns.

## CerfEmulator

The composition root. One C++ class, owned by `main.cpp`, owns every service.
Multi-instance by construction — two `CerfEmulator` instances inside the same
host process share nothing and can boot different device profiles side by
side. Services are resolved via `emu.Get<T>()`; statics and globals for
service state are forbidden.

— `cerf/core/cerf_emulator.h`, `cerf/core/service.h`

## ARM JIT

ARM machine code runs through a block JIT. Every ROM binary —
`nk.exe` / `coredll.dll` / `gwes.exe` / `filesys.exe` / `device.exe` /
userspace EXEs / driver DLLs — is the original ARM code, translated
to host machine code on the fly. Both ARM-mode and Thumb-mode go
through the same `ArmJit` service; there is no per-SoC `ArmJit`
strategy. Per-SoC variation (PC store offset, base-restored-abort
model, cache-line size, MIDR/CTR values, coprocessor emit shape)
lives in `ArmProcessorConfig` and `CoprocEmitter` strategies
selected by SoC family — never as `if (soc == X)` branches inside
the JIT body.

The JIT subsystem is its own service constellation under `cerf/jit/`:
`ArmJit`, `ArmCpu`, `ArmMmu`, `ArmDecoder`, `ArmProcessorConfig`,
`CoprocEmitter`, `ArmCp15SctlrHandler`, `JitRunner`. Full design
notes — the `place_fn` contract, the pinned-register dispatcher,
the compile pipeline, the trampoline pattern, FCSE fold, shadow
stack, cross-thread interrupt delivery, SEH fault filter — live at
[agent_docs/jit.md](jit.md).

— `cerf/jit/`, [agent_docs/jit.md](jit.md)

## Per-chip / per-board / per-part strategies

CERF splits per-impl code across three orthogonal trees, picked by the
nature of the thing being implemented.

### `cerf/socs/<chip>/` — on-die silicon

One directory per SoC family (S3C2410 today; PXA27x, OMAP3530, SA-1110,
Poseidon, … added when their boards land). Contains:

- per-peripheral `<chip>_*.cpp` — UART, INTC, GPIO, RTC, timer, watchdog,
  clock/power, memory controller, LCD controller, NAND controller, IIS,
  etc.

Concretes' `ShouldRegister` checks
`emu_.Get<BoardDetector>().GetSoc() == SocFamily::X`. Chip-layer code
never knows which board it's on — only which chip.

The VA→PA placement map (`PageTableBuilder`) and the MMU base-mask policy
(`MmuPolicy`) are **not** here. VA→PA placement is a BSP/board choice (the
OEMAddressTable), so its concretes live under `cerf/boards/<board>/`; the
MMU base-mask is a CPU-arch property, so its concretes live under
`cerf/cpu/<arch>/`. Both are selected by `GetBoard()`, not `GetSoc()`.

### `cerf/boards/<board>/` — one specific OEM board / BSP

One directory per supported board. Contains:

- `<board>_detector.cpp` — the concrete `BoardDetector` impl (heuristically
  fingerprints the ROM bundle by a board-unique driver-blob signature in
  the TOC; reports `Board` and `SocFamily` constants for that board)
- `<board>_page_table_builder.cpp` — the board's `PageTableBuilder` impl:
  the BSP OEMAddressTable VA→PA map, DRAM/flash backed regions, and the
  bootloader-handoff SP, used for ROM placement and pre-MMU boot
- board-only virtual peripherals — host-emulator notification channels,
  virtual DMA transports, folder-sharing helpers (peripherals that exist
  only because the board's BSP expects the emulator to provide them)
- BSP-specific config writers (e.g. `<board>_bsp_args.cpp` populating a
  DRAM struct the BSP reads on boot)

Concretes' `ShouldRegister` checks
`emu_.Get<BoardDetector>().GetBoard() == Board::X`. A board's BoardDetector
is the only thing that has to know its board name; everything else just
asks "am I on board X".

### `cerf/peripherals/<vendor>_<part>/` — off-chip silicon shared across boards

One directory per off-chip IC family. Today: `cirrus_pd6710/` (PCMCIA
controller), `amd_am29lv800bb/` (NOR flash). Tomorrow's additions go in
new sibling directories (e.g. `davicom_dm9000/` for the DM9000 NIC IC).

Concretes' `ShouldRegister` checks a board-list:

    auto b = emu_.Get<BoardDetector>().GetBoard();
    return b == Board::X || b == Board::Y;

The list grows when a new board adopts the same part — the part file is
never duplicated, and the part directory is the single source of truth
for what the IC does.

The `cerf/peripherals/` root (not under any vendor subdir) also holds
the abstract `Peripheral` base (`peripheral_base.{h,cpp}`) and the
MMIO router (`peripheral_dispatcher.{h,cpp}`). All peripheral-domain
code — framework and concretes — lives in this one tree.

### Trees vs bases

Abstract bases (`BoardDetector`, `PageTableBuilder`, `MmuPolicy`,
`Peripheral`) live next to their consumers (`cerf/boards/`, `cerf/core/`,
`cerf/cpu/`, `cerf/peripherals/`), not under any per-impl tree.

Adding or removing a chip / board / vendor-part touches exactly one
directory. Splitting one impl's pieces across multiple trees (chip
pieces in board dir, board pieces in chip dir) is the wrong axis and is
itself the tech-debt shape this layout exists to prevent.

— `cerf/socs/`, `cerf/boards/`, `cerf/peripherals/`

## Host window & presentation

The Win32 window, its drawable area, and the render/input plumbing that
connects the host UI to the guest. All are `Service`s; the renderer,
touch, and keyboard pieces are abstract bases with per-SoC/per-board
concretes (strategy pattern, selected by `BoardDetector`).

- **`HostWindow`** — the top-level window. Owns the dedicated UI thread
  (window + message pump live there, not the main thread), the menu, and
  auto-resize-to-guest. The SoC LCD service calls `OnLcdEnabled` on the
  guest panel-enable edge to size the window to the guest surface.
  — `cerf/host/host_window.{h,cpp}`

- **`HostCanvas`** — the child window for the drawable area. Owns the two
  **tabs** (`Tab::Uart` = boot/debug-console screen, `Tab::Framebuffer` =
  the live guest framebuffer), the viewport mode (Original / Aspect /
  Stretch, optional antialias), the scrollbars, and the single
  host-pixel↔guest-surface coordinate transform (`HostToGuest`) so taps
  land on the rendered image. Publishes the atomic guest-surface
  dimensions the touch sampler reads. — `cerf/host/host_canvas.{h,cpp}`

- **`FrameRenderer`** (abstract) — `RenderInto(dib_bgra32, w, h)` fills a
  BGRA32 guest-surface DIB; `HostSizeFor` lets a rotating renderer swap
  width/height. Concretes live with the hardware that produces the frame:
  per-SoC LCD/DSS/IPU renderers under `cerf/socs/<chip>/`, board renderers
  under `cerf/boards/<board>/`, and the guest-additions virtual framebuffer
  under `cerf/peripherals/cerf_virt/`. — `cerf/host/frame_renderer.h`

- **`UartScreen`** — the bounded debug-console line buffer behind the Uart
  tab; `AddLine` from the SoC UART, `RenderInto` paints the boot log + boot
  bar. `HasOutput` is the splash→boot-log transition trigger.
  — `cerf/host/uart_screen.{h,cpp}`

- **`TouchInput`** (abstract) — `OnPenDown/Move/Up` + `OnCaptureLost` in
  guest-surface coordinates; the board's touch peripheral concrete turns
  them into guest pen samples. Concretes under `cerf/boards/<board>/`.
  — `cerf/host/touch_input.h`

- **`KeyboardInput`** (abstract) — `OnHostKey(vk, key_up)`; the board's
  keyboard peripheral concrete maps host VKs to the guest. Concretes under
  `cerf/boards/<board>/`. — `cerf/host/keyboard_input.h`

- **`HostInputCapture`** — the low-level keyboard hook + capture toggle (so
  the guest receives keys the host shell would otherwise eat); forwards to
  `KeyboardInput` and synthesizes Ctrl-Alt-Del. Installed/removed on the UI
  thread. — `cerf/host/host_input_capture.{h,cpp}`

- **`HostStatusBar`** — the bottom status bar. Renders the
  `HostWidgetRegistry`'s ordered widget set (icons + per-icon tooltips,
  left-click → primary action, right-click → declarative popup); the
  capture/lock indicator is itself one such (host-owned) widget.
  — `cerf/host/host_status_bar.{h,cpp}`

- **`HostWidget` / `HostWidgetRegistry`** — the status-bar + Actions-menu
  widget framework. `HostWidget` is an abstract, **non-`Service`** interface
  (so a `Peripheral`, which already derives `Service`, can implement it
  without a diamond) that any service implements to declare a host-UI
  presence: a custom GDI icon, tooltip, left-click action, declarative
  right-click menu (replicated into the Actions menu), hot-path-safe RX/TX
  activity dots, an `IsEnabled()` grayscale seam, and a `WidgetGroup`
  ordering key (the terminal `InputControl` group pins rightmost).
  Implementers self-register with `HostWidgetRegistry` from `OnReady`, the
  same way peripherals self-register with `PeripheralDispatcher`;
  `HostStatusBar` renders the ordered set and concretes follow the three-tree
  rule (`cerf/socs|boards|peripherals/`). Reach for it whenever a peripheral
  or board has user-visible state (RX/TX, enabled/disabled) or a
  configuration/toggle surface. — `cerf/host/host_widget*.{h,cpp}`

- **`HostScreenshot`** — screenshot + clipboard capture of the live guest
  surface (via `HostCanvas::CaptureGuestSurface`, 1:1).
  — `cerf/host/host_screenshot.{h,cpp}`

## TraceManager

Always-built developer debugging facility for putting in-host C++ handlers
behind specific guest PC addresses, guest memory addresses, and per-JIT-Run
iteration ticks — without polluting permanent code with bug-specific
diagnostics. Hot paths are zero-overhead when no traces are registered
(empty-container short-circuit; production builds register nothing).

Two hook surfaces:

- **PC trace** (`OnPc(runtime_va, handler)`) — handler fires once per
  execution of the guest instruction at `runtime_va`. Implemented in
  the JIT block compiler (`cerf/jit/arm_jit_generate_code.cpp`): for
  each decoded instruction at compile time, if
  `TraceManager::HasPcTrace(pc)` returns true, the compiler emits an
  x86 `CALL` to `ArmJit::TraceDispatchPcHelper` immediately before the
  instruction's `place_fn` emit; the helper routes through
  `TraceManager::DispatchPc(pc, regs, cpsr)`. The trace call is
  placed inside the same cond-guarded region as the instruction's
  emit — for conditional ARM instructions, the trace fires iff the
  condition is true at runtime, the same condition under which the
  guarded instruction itself executes.
- **RunLoop iter** (`OnRunLoopIter(handler)`) — handler fires after each
  `ArmJit::Run()` return in `JitRunner::RunLoop`. Used for value-change
  pollers and one-shot startup audits.

**There is no OnRead / OnWrite memory-watch primitive.** A prior
design exposed one and it was a footgun: every watched VA forced
every memory access on the containing 4 KB page through an MMU walk
+ PeripheralDispatcher + EmulatedMemory + dispatch callback chain
instead of the JIT's GuestTlb fast path, slowing those accesses
30-50×. The cumulative slowdown shifted guest IRQ delivery
alignment relative to the kernel scheduler, and that shift CREATED
Heisenbug-shaped races / deadlocks that did NOT exist in production
CERF. The wm5_smdk2410_devemu boot-stall investigation burned 20+
human hours chasing one of these — production builds (trace files
excluded) reproduced zero stalls in 15 runs, dev builds with one
OnWrite on a thread-descriptor page stalled 20-40% of runs.

"Move the watch to a less-hot page" doesn't solve it — any
page-exclusion shifts the timing race somewhere else where it can
manifest as a different false bug. There is no safe page. The
mechanism itself is what's unsafe.

To observe a memory write, hook `OnPc` at the writer instruction PC
and read the freshly-written value via `c.ReadVa8 / 16 / 32(va)` on
the `TraceContext` inside the handler (these go through
`ArmMmu::PeekDataTlb`, GuestTlb fast-path only, no side effects).
For values whose writer PC is unknown, poll via `OnRunLoopIter` (no
per-access overhead between `ArmJit::Run()` returns). For all
writers of a value, attach `OnPc` to each writer site individually.

`TraceContext` (passed to every handler) carries the 16 GPRs, CPSR, PC, and
a `CerfEmulator&` for service access. `ReadVa8 / 16 / 32` are read-only
GuestTlb-fast-path peeks (no MMU side effects, return `std::nullopt` for
pages not currently fast-path-mapped).

— `cerf/tracing/trace_manager.{h,cpp}` + new `Trace` log channel.

## Device-specific trace files

`cerf/tracing/<bundle>/*.cpp` — one subdirectory per device bundle.
Each file is a small `Service` whose `OnReady` calls
`TraceManager::RegisterForBundle(<expected_crc32>, register_fn)`. The
closure runs iff the live bundle's CRC32 matches; otherwise the file
silently no-ops at runtime. `<bundle>/bundle.h` (or `wm5_bundle.h` etc.)
declares `constexpr uint32_t kBundleCrc32 = ...;` used by every trace file
in that directory.

The bundle CRC32 is computed by `TraceManager::OnReady` over the
concatenated `RomParserService::Loaded()[i].raw` bytes in load order. On
first boot for a new bundle, the log line `[TRACE] bundle CRC32 = 0xXXXX`
gives you the value to paste into the trace file's `bundle.h`.

`build.ps1 -Mode production` excludes the per-device trace files from the
build via a `<ClCompile Remove="tracing\*\**\*.cpp">` rule in
`cerf/cerf.vcxproj`. The framework (`cerf/tracing/trace_manager.{h,cpp}`)
stays compiled; with no registered traces, every hook is a single
empty-container check.

— `cerf/tracing/<bundle>/`

## Bundled device tree

`bundled/devices/<name>/` is the input CERF reads at boot:

- A Windows CE ROM image, `*.nb0` or `*.bin`. CERF picks up whichever
  is present; the filename does not matter.
- `cerf.json` — per-device runtime configuration. The `meta` block
  identifies the device (display name, board name, SoC family, OS
  name + version, year — used by the launcher and status displays).
  Optional `board` / `network` / `rom` blocks override `DeviceConfig`
  defaults. A missing file means CERF uses `DeviceConfig` defaults
  plus CLI overrides.

`bundled/devices/` is synced via `bundled/devices/sync_bundles.py`,
which downloads the public manifest and installs selected bundles.
Downloaded bundle directories and the local `manifest.json` are
ignored by Git — only those are copied to the release directory; users
run `sync_bundles.py` locally. Never run `sync_bundles.py` on your own.

For IDA debugging, the same `.nb0` / `.bin` is decomposed offline by
`tools/extract_bundles.py` (runs `references/extract-wince-rom`
against each ROM and copies any matching PDBs in) into
`references/extracted-roms/<dev>/<rom>/`. That tree is gitignored,
not consumed by CERF at runtime, and exists solely for IDA / static
analysis — see `agent_docs/debugging.md` § IDA discipline.

Build-time staging mirrors `bundled/**/*` into `build/<config>/x64/**`
via the `CopyBundledFiles` MSBuild target (incremental, never deletes
destination files absent from the source set).

## CE Apps — CERF-built ARM CE binaries

`ce_apps/<name>/` directories build small Windows CE ARM EXEs and DLLs
against the per-CE-era SDKs in `references/WindowsCE-Build-Tools/`
(`ce3-oak` … `ce7-oak`). Used as bundled samples; in v1 they drove the
test harness. Each directory has a `main.c` and a one-line `build.ps1` that
delegates to `tools/build_ce_app.ps1`; the top-level `build.ps1` walks
every `ce_apps/*/build.ps1` after msbuild succeeds. Outputs land at
`build/<Config>/Win32/ce_apps/<name>.{exe,dll}`. Today it hosts the
`cerf_guest` guest-additions display driver (below) alongside sample
binaries; it is the home for any CERF-built CE binary.

## Guest Additions display driver — `ce_apps/cerf_guest/`

The universal CERF display driver, injected into the guest ROM at load time by
`--guest-additions` (the ROM parser swaps it in for the board's stock display
driver). Built from real CE driver sources against the CE6 DDGPE/GPE libraries;
a compatibility shim under `ce_apps/cerf_guest/shim/` reshapes the
driver-interface data at the OS boundary so the single CE6-based driver runs
unmodified across CE3 → CE7 and Windows Mobile 5/6 (each OS sees its own
generation's shapes; the driver always sees CE6 shapes).

It is the guest-side partner of the host `cerf/peripherals/cerf_virt/` virtual
framebuffer + `gpe_cmd` accelerator channel: the driver routes blits over that
channel and the host performs them natively (see `cerf_ddgpe.cpp` for the
`BltPrepare` routing, `main.cpp` for the channel ABI). What it owns today is the
universal display path — host-framebuffer rendering plus host-accelerated blits.
Planned growth is host-side GPU acceleration, runtime screen resize, host↔guest
shared storage / clipboard, and a guest-additions input path. Reference behavior
for the blit pipeline is the CE6 GPE source under
`references/WINCE600/.../DISPLAY/` (GPE `swblt.cpp`/`swconvrt.cpp`, EMUL `eb*.cpp`).
