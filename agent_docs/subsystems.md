# CERF Subsystems

The host-side subsystem set is small. CE-side binaries (kernel, OAL, drivers,
userspace) run unmodified as guest code through the JIT. They are not host
subsystems. This page lists what CERF itself owns.

## CerfEmulator

The composition root. One C++ class, owned by `main.cpp`, owns every service.
It is multi-instance by construction. Two `CerfEmulator` instances inside the
same host process share nothing. They can boot different device profiles side
by side. `emu.Get<T>()` resolves a service. Statics and globals for service
state are forbidden.

### Service locator mechanics

- **Registration is one macro line per `.cpp`**: `REGISTER_SERVICE(Foo)`
  (resolvable only as `Foo`), `REGISTER_SERVICE_AS(Foo, Base)` (a candidate
  for the `Base` slot, also resolvable as `Foo` - the strategy pattern),
  `REGISTER_SERVICE_AS_FALLBACK(Foo, Base)` (wins only if `ShouldRegister`
  returned true for no non-fallback candidate). Boot then constructs every
  candidate. Boot runs the `ShouldRegister` of each slot to pick the single
  winner. Boot then calls `EnsureReady` on **every** winner.
- **The `OnReady` of every winning service runs exactly once**, at boot. It
  runs whether or not anything ever calls `Get<>` for it. The boot sweep
  calls `EnsureReady` on all winners. A service that only connects itself
  (registers MMIO, starts a worker) still initializes with no external
  caller. `OnReady` is also lazy. A first `Get<Dep>()` from inside your
  `OnReady` runs `Dep::OnReady` before it returns, so the graph self-orders
  on demand. Both paths guard with a mutex, so `OnReady` never runs twice.
  There is no init phase, no declared order, and no pre-warm step. A bare
  `(void)emu_.Get<X>()` to force materialization is forbidden (`rules.md`).
- **If no candidate won the slot, `Get<T>()` is fatal.** **`TryGet<T>()`**
  returns `nullptr` for an optional dependency. Both resolve lazily and call
  `EnsureReady`.
- **Misuse calls `CerfFatalExit` with the types named**: two `ShouldRegister`
  true for one Base, a required slot with no winner, or a
  `ShouldRegister`↔`Get` cycle. You need no defensive check around `Get<>`.
- **`ShouldRegister()`** can call `Get<>`/`TryGet<>` through the same lazy
  path. The idiom is `emu_.Get<BoardContext>().GetSoc() == SocFamily::X`.

- `cerf/core/cerf_emulator.h`, `cerf/core/service.h`

## Guest CPU JIT

Guest code runs through a block JIT. Every ROM binary is the original guest
code, translated to host x86 on the fly. This covers
`nk.exe` / `coredll.dll` / `gwes.exe` / `filesys.exe` / `device.exe` /
userspace EXEs / driver DLLs. `JitRunner` drives an abstract `GuestEngine`
service. The concrete engine implements it for the CPU architecture of the
board, and `BoardContext::GetCpuArch()` selects it. Per-SoC variation lives
in per-core strategy services that `GetSoc()` selects. Per-SoC variation is
never an `if (soc == X)` branch in the JIT body.

- `cerf/jit/`, [agent_docs/jit.md](jit.md)

## Per-chip / per-board / per-part strategies

CERF splits per-impl code across three orthogonal trees. The nature of the
implemented thing selects the tree.

### `cerf/socs/<chip>/` - on-die silicon

One directory per SoC family (S3C2410 today. PXA27x, OMAP3530, SA-1110,
Poseidon, … arrive with their boards). It contains:

- per-peripheral `<chip>_*.cpp` - UART, INTC, GPIO, RTC, timer, watchdog,
  clock/power, memory controller, LCD controller, NAND controller, IIS,
  and more.

The `ShouldRegister` of a concrete returns
`emu_.Get<BoardContext>().GetSoc() == SocFamily::X`. Chip-layer code
never knows its board. It knows only its chip.

The VA→PA placement map (`PageTableBuilder`) is **not** here. The core
CPU strategies (`ArmProcessorConfig`, `CoprocEmitter`) split on a different
axis. VA→PA placement is a BSP/board choice, because the OEMAddressTable
differs per board. Its concretes live under `cerf/boards/<board>/`, and
`GetBoard()` selects them. The core strategies are a CPU-arch property
identical across every board on that core. Their concretes live under
`cerf/cpu/<core>/`, and `GetSoc()` selects them. A core strategy gated on
`GetBoard()` leaves every additional board on that SoC with no winner. A
second SA-1110 board that re-states the MIDR of the die is the smell.

### `cerf/boards/<board>/` - one specific OEM board / BSP

One directory per supported board. It contains:

- `<board>_context.cpp` - the concrete `BoardContext` impl. It reports the
  `Board`, `SocFamily`, `CpuArch`, and `RomPlacingMode` constants for that
  board. It registers when the configured `board_id` names it
- `<board>_page_table_builder.cpp` - the `PageTableBuilder` impl of the
  board: the BSP OEMAddressTable VA→PA map, the DRAM/flash backed regions,
  and the bootloader-handoff SP. ROM placement and pre-MMU boot use it
- board-only virtual peripherals - host-emulator notification channels,
  virtual DMA transports, folder-sharing helpers. These peripherals exist
  only because the BSP of the board expects the emulator to provide them
- BSP-specific configuration writers (for example `<board>_bsp_args.cpp`,
  which fills a DRAM struct that the BSP reads on boot)

The `ShouldRegister` of a concrete returns
`emu_.Get<BoardContext>().GetBoard() == Board::X`. The BoardContext of a
board is the only thing that must know its board name. Everything else asks
only "am I on board X".

### `cerf/peripherals/<vendor>_<part>/` - off-chip silicon shared across boards

One directory per off-chip IC family. Today: `cirrus_pd6710/` (PCMCIA
controller), `amd_am29lv800bb/` (NOR flash). Future additions live in
new sibling directories (for example `davicom_dm9000/` for the DM9000 NIC IC).

The `ShouldRegister` of a concrete compares against a board list:

    auto b = emu_.Get<BoardContext>().GetBoard();
    return b == Board::X || b == Board::Y;

The list grows when a new board adopts the same part. The part file is
never duplicated. The part directory is the single source of truth
for what the IC does.

The `cerf/peripherals/` root (not under any vendor subdir) also holds
the abstract `Peripheral` base (`peripheral_base.{h,cpp}`) and the
MMIO router (`peripheral_dispatcher.{h,cpp}`). All peripheral-domain
code - framework and concretes - lives in this one tree.

### Trees vs bases

Abstract bases (`BoardContext`, `PageTableBuilder`,
`Peripheral`) live next to their consumers (`cerf/boards/`, `cerf/core/`,
`cerf/cpu/`, `cerf/peripherals/`), not under any per-impl tree.

To add or remove a chip / board / vendor-part, you touch exactly one
directory. A split of the pieces of one impl across multiple trees (chip
pieces in board dir, board pieces in chip dir) is the wrong axis. That split
is itself the tech-debt shape that this layout prevents.

**Place code by what the behavior IS, not by which file is safe to
touch.** A property identical across every board on a core (instruction
semantics, clock / power behavior, MMU / exception behavior) is a
CPU-arch / SoC fact. It belongs in the SoC / CPU / JIT layer, even when
that means an edit to the most fragile shared code. A push of that property
into a board-local carve-out to avoid the shared file is architecture
destruction, not faithfulness. The words "faithful" and "minimal" on such a
carve-out do not change that.

- `cerf/socs/`, `cerf/boards/`, `cerf/peripherals/`

## PCMCIA

16-bit PC Card emulation, split framework/controller/card:

- **`PcmciaCard`** (`cerf/peripherals/pcmcia/pcmcia_card.h`) - the abstract
  card: attribute/common/IO surface, PowerOn/Off, SocketReset, optional
  `BuildCardMenu`. Cards are plain objects (NOT Services).
  `PcmciaCardCatalog::Create()` creates a card, and its slot owns it. One
  type can occupy two slots at once. Concretes:
  `cerf/peripherals/realtek_rtl8019/` (NE2000 NIC),
  `cerf/peripherals/compactflash/` (PC Card ATA + FAT32 image builder +
  insert submenu), `cerf/peripherals/serial_pccard/` (16550 serial /
  modem card - the PC-card consumer of the Serial stack on this page).

  **A card releases its pins in `PowerOff` / `OnShutdown`, NEVER in a
  destructor.** Nothing ejects a card at shutdown. The card dies inside the
  destructor of its controller, when the members of that controller are
  already gone. A line dropped from a card dtor therefore reaches into freed
  state. And **no Vcc means a card drives no pin, its interrupt included** (the
  socket floats its data lines on the same rule). A card with its own
  host or network thread gates its interrupt on power. If it does not, it
  strands a line on a socket that it already left.
- **`PcmciaSlot`** (`pcmcia_slot.{h,cpp}`) - one physical socket. It owns
  card lifetime and bus serialization. It IS the HostWidget with the
  universal Insert/Eject/Eject-and-insert menu. The controller that owns the
  slot implements **`PcmciaSlotHost`** (card-detect / IRQ callbacks) and
  routes guest accesses to the Read/Write surface of the slot.
  **Card-detect and Vcc (`HasCard` / `IsPowered`) are lock-free reads of
  an atomic pin word, published under the bus lock - keep them that way.**
  A controller reads them from inside its own lock. At the same time, eject
  runs bus lock -> card -> IRQ callback -> that same controller lock. A pin
  accessor that took the bus lock closes an AB-BA against the UI thread.
  Every other slot entry point is a bus transaction, and a host calls it
  with its own lock released.
- **`PcmciaCardCatalog`** (`pcmcia_card_catalog.{h,cpp}`) - the
  insert-menu card registry. A new card type is one `PcmciaCard`
  subclass plus one catalog entry.
- **`PcmciaSpaceRouter`** (`pcmcia_space_router.{h,cpp}`) - the shared
  SA-1110/PXA255 static-window PC Card space decode (PA 0x20000000,
  socket/region bits). Controllers call `ProvideSockets`. Never
  re-implement this decode per SoC.

To wire a new board, write a socket controller in the proper tree
(chip/board/vendor-part). That controller owns `PcmciaSlot` instances,
implements `PcmciaSlotHost`, registers the slots with `HostWidgetRegistry`,
and drives `SetPowered` from its power register. For examples, see
`cirrus_pd6710/` (DevEmu), `intel_sa1111/sa1111_pcmcia.cpp` (Jornada),
`ipaq_gen1_pcmcia_sleeve.cpp`, `falcon_pcmcia.cpp`.

- `cerf/peripherals/pcmcia/`

## Serial

The serial stack that any UART can use. The same endpoints serve an
on-SoC UART and a serial PC card. A board therefore gains ActiveSync /
dial-up through one interface. The stack splits into line and personality:

- **`SerialLine`** (`cerf/peripherals/serial/serial_line.h`) - the abstract
  UART surface that an endpoint drives: push RX, read the line configuration
  of the guest (baud/framing), raise modem-status inputs, drain callbacks.
  Concretes: **`Serial16550`** (the PC16550D model that the `ser16550`
  MDD/PDD of the ROM drives unmodified) and any SoC UART peripheral that
  implements it.
- **`SerialEndpoint`** (`serial_endpoint.h`) - the "personality" behind a
  line. It consumes guest TX, reacts to DTR/RTS, and pushes RX and modem
  status back. Concretes: **`HostSerialForward`** (bridges to a real host
  COM port - overlapped I/O, baud-faithful TX pacing) and
  **`ModemPersonality`** (AT command set -> **`PppTerminator`** ->
  libslirp). There is one endpoint per attach point, owned by whatever
  holds the line.
- **`SerialCradle`** (`serial_cradle.{h,cpp}`) - the HostWidget for an
  on-SoC UART. It mirrors the insert/eject flow of `PcmciaSlot` and shares
  its card menus. A modem attached to the serial port of a board therefore
  looks like an inserted card. The UART peripheral owns it. It is not a
  Service.
- `cerf/peripherals/serial_pccard/` holds ONLY the PC-card consumer. The
  framework named here is board-neutral and lives in
  `cerf/peripherals/serial/`.

To wire the stock UART of a board, implement `SerialLine` on the UART
peripheral (RX path + an RX interrupt + baud from its divisor + modem
status on whatever pins the board wires). Own a `SerialCradle`. Supply a
per-board seam that names the modem pins. Take those pin numbers from the
serial driver of the board. Never guess them.

- `cerf/peripherals/serial/`

## CPU reset & cold boot

**`GuestCpuReset`** is the funnel for every CERF-initiated CPU reset
(host reset actions, watchdog expiry). Never call bare
`ArmJit::SetResetPending`. The SoC peripheral that owns the reset-cause
register implements `ResetCauseLatch` (warm / cold / watchdog), so the
re-entered guest boot path reads a true reset cause. Peripherals whose
silicon resets with the system reset line register reset listeners that run
at reset delivery on the JIT thread. One such peripheral is a drive that
re-presents its power-on diagnostic signature. A board without this wiring
boots, but it hangs on guest reboot. A startup that reads the reset cause
takes the sleep-resume path, and warm peripheral state fails driver
re-probes.

- `cerf/socs/guest_cpu_reset.{h,cpp}`

**`GuestColdBoot`** implements hard reset (cold boot). At reset
delivery it wipes every volatile RAM region (flash survives), replays
registered boot-time guest-RAM writes in registration order, and
flushes the translation cache. Every service that writes guest RAM
during `OnReady` (ROM placement, BSP_ARGS blocks, image injection)
MUST register a replay. When the computation that produces the bytes
allocates and must not run again, register a byte-exact `RecordPatch`
instead. Without one of the two, the bytes of that service are silently
absent after every hard reset on that board.

- `cerf/boot/guest_cold_boot.{h,cpp}`

## Host window & presentation

The Win32 window, its drawable area, and the render/input plumbing that
connects the host UI to the guest. All are `Service`s. The renderer,
touch, and keyboard pieces are abstract bases with per-SoC/per-board
concretes (strategy pattern, selected by `BoardContext`).

- **`HostWindow`** - the top-level window. It owns the dedicated UI thread
  (window + message pump live there, not the main thread), the menu, and
  auto-resize-to-guest. The SoC LCD service calls `OnLcdEnabled()` on the
  guest panel-enable edge. The call carries no dimensions. The call tells the
  host to read the new size from `FrameRenderer::PresentedSize`.
  - `cerf/host/host_window.{h,cpp}`

- **`HostCanvas`** - the child window for the drawable area. It owns the
  **tabs** (`Tab::Boot` = boot screen, `Tab::Hw` = hardware text console,
  `Tab::Framebuffer` = the live guest framebuffer, `Tab::MemoryVisualizer` =
  dev), the viewport mode (Original / Aspect / Stretch, optional antialias),
  and the scrollbars. It also owns the single host-pixel↔guest-surface
  coordinate transform (`HostToGuest`), so taps land on the rendered image.
  The startup tab is `DeviceConfig.start_tab` (`--tab=boot|hw|fb`). On the
  first presented guest frame the canvas auto-switches to `Tab::Framebuffer`,
  unless the user already picked a tab. `Tab` is an alias of the core
  `CanvasTab` enum, so core configuration can name the startup tab with no
  dependency on the host layer. The canvas publishes the atomic
  guest-surface dimensions that the touch sampler reads.
  - `cerf/host/host_canvas.{h,cpp}`

- **`FrameRenderer`** (abstract) - one producer of guest frames.
  `RenderInto(dib_bgra32, w, h)` fills a BGRA32 surface. `PresentedSize(w, h)`
  gives the extent of the image that this producer renders. The extent is
  already in presented orientation, so a renderer that rotates the image
  reports the swapped extent.

  **`PresentedSize` is the only authority on the panel-enable edge.**
  `HostWindow::OnLcdEnabled()` carries no dimensions. It posts to the UI
  thread, and the UI thread reads the size through `PresentedSize`. A
  peripheral must never pass its own dimensions to the host. A renderer can
  draw at a different extent than the panel timing. If a peripheral passes its
  own dimensions, the window size disagrees with the image.

  The size read stays on the UI thread by construction. A publisher usually
  reaches `OnLcdEnabled()` with its own peripheral lock held, and
  `PresentedSize` goes back into that same peripheral. A read on the
  publishing thread therefore re-locks a non-recursive mutex. That wedges the
  JIT thread and the UI thread together.

  `PresentedSize` is not the only source of the guest-surface size.
  `HostCanvas::SetGuestSurfaceSize` is the single entry point, and the
  panel-enable edge is only one of its callers.
  `HostWindow::SetGuestResolution` calls it for a guest re-mode and for the
  resolution dialog. `HostAutoResize::OnUserResizeEnd` reaches it through that
  same path, and is not a separate setter.
  `Hibernation::RestorePresentation` calls it with the size from the state
  image. A restore therefore installs a surface size that `PresentedSize`
  never produced.

  Three slots build on this base:

  - **`PanelFrameRenderer`** - the physical panel scanout of the board. Every
    hardware renderer registers here. Its `ShouldRegister` gates on hardware
    presence only (board, SoC or part). It never gates on guest additions.
    Concretes live with the hardware that produces the frame: per-SoC
    LCD/DSS/IPU renderers under `cerf/socs/<chip>/`, board renderers under
    `cerf/boards/<board>/`, off-chip display parts under
    `cerf/peripherals/<vendor>_<part>/`.
  - **`GuestAdditionsFrameRenderer`** - the guest-additions virtual
    framebuffer under `cerf/peripherals/cerf_virt/`. It wins only on a
    `--guest-additions` run.
  - **`FrameRenderer`** itself - the presented surface. It has one candidate,
    **`PresentedFrameRenderer`**, and `HostCanvas` binds it.

  **`PresentedFrameRenderer`** is an ordered stack of the two layers above.
  The panel layer renders under the guest-additions layer. A splash that the
  bootloader or the kernel draws therefore stays visible until the
  guest-additions display driver renders its first frame. The boot animation
  of CERF is only the placeholder while the guest renders nothing.

  The compositor scales a smaller layer up by the largest integer factor that
  fits, and then centers it. One factor serves both axes, so the aspect ratio
  stays exact. Nearest-neighbor sampling keeps each source pixel square.

  The layers are opaque, and the compositor skips each covered layer. DO NOT
  blend the layers per pixel. The guest-additions surface has areas that are
  legitimately black, and a blend makes the panel layer visible through them.

  The layer that covers the surface renders directly into the target DIB, so
  it costs no copy. The scratch buffer and the scaled copy occur only while
  the compositor presents a smaller layer.

  `RearmContentLatch` goes to every layer, so a guest reset rearms all of
  them.

  To add a layer, register it on its own role slot. Then put the layer in the
  order of the compositor.
  - `cerf/host/frame_renderer.h`, `panel_frame_renderer.h`,
    `guest_additions_frame_renderer.h`, `presented_frame_renderer.cpp`

- **`HwScreen`** - the hardware text console behind the `Tab::Hw` tab. It is
  the bounded text-mode RX/TX line buffer for guest UART / OEM-debug output
  and for the notices of CERF itself (power events, save/restore progress).
  `AddLine` appends a line. `RenderInto` draws the scrolled log over the
  `BootBar`.
  - `cerf/host/hw_screen.{h,cpp}`

- **`BootScreen`** - the CERF-logo boot animation behind the `Tab::Boot` tab,
  plus the `BootBar`. The 60 Hz present loop drives it in time, with no
  thread. `Restart` (guest reboot / deep-sleep wake) and
  `OnFramebufferLatched` are its cross-thread control hooks.
  - `cerf/host/boot_screen.{h,cpp}`

- **`BootBar`** - the bottom CPU-activity bar shared by the Boot Screen and
  Hardware Screen tabs. It is a strip that scrolls. The host animation clock
  advances it, so it freezes when emulation is paused.
  - `cerf/host/boot_bar.{h,cpp}`

- **`TouchInput`** (abstract) - `OnPenDown/Move/Up` + `OnCaptureLost` in
  guest-surface coordinates. The touch peripheral concrete of the board
  converts them into guest pen samples. Concretes live under
  `cerf/boards/<board>/`.
  - `cerf/host/touch_input.h`

- **Off-screen bezel touch buttons are physical, never framebuffer-drawn.**
  Some resistive-panel boards (Jornada 720, Casio Toricomail) print soft
  buttons on the bezel, over the digitizer and outside the LCD area. The
  guest does not render them. They are extra areas of the same touch panel,
  in a raw-ADC band past the screen's active range. The board maps its screen
  to a raw sub-range (a per-board seam) and reserves the rest of the range for
  the buttons. A host menu (the keyboard-widget hotkey section) sends a held
  synthetic raw pen tap to each button, because no on-screen pixel maps to one.
  The guest driver resolves the zone-to-key mapping and its own calibration.
  CERF models only the panel geometry, never the guest's button table.

- **`KeyboardInput`** (abstract) - one keyboard source: `OnHostKey(vk, key_up)`
  plus `SourceName` / `SourcePriority` / `SourceReady`. Concretes self-register
  with `KeyboardRouter`. They are the keyboard of a board under
  `cerf/boards/<board>/` and the guest-additions keyboard under
  `cerf/peripherals/cerf_virt/`.
  - `cerf/host/keyboard_input.h`

- **`KeyboardRouter`** - the keyboard-source registry and host-key funnel.
  `KeyboardInput` concretes self-register from `OnReady`. The router forwards
  host keys to the single active source.

  **The router selects the highest-priority source that reports
  `SourceReady`.** When no source is ready, the router selects the highest
  priority overall. A board with no stock keyboard must not have dead input.

  `RearmAutoSelect` re-runs that selection and drops any manual choice. A guest
  reset calls it, so the stock keyboard is active again until a source reports
  `SourceReady`. `ReevaluateAuto` re-runs the selection and keeps a manual
  choice.

  When more than one source is registered, the `KeyboardWidget` status-bar
  widget switches the active source. That switch is a manual choice, and it
  suppresses automatic selection until the next reset. The widget keeps the
  choice across hibernation.
  - `cerf/host/keyboard_router.{h,cpp}`

- **`PointerRouter` / `PointerWidget`** - the pointer-source registry and
  host-mouse funnel. It mirrors `KeyboardRouter`. Pointing-device sources
  (the touch / mouse of a board, the guest-additions absolute pointer)
  self-register. The router forwards host mouse messages to the single
  active source. It selects by the same ready-then-priority rule as
  `KeyboardRouter`, and it carries the same `RearmAutoSelect` /
  `ReevaluateAuto` pair.
  When more than one is registered, the `PointerWidget` status-bar widget
  switches the active source and keeps the choice across hibernation. Some
  apps (calibrators) read the stock touch/mouse stream directly. On a board
  whose stock pointer is a relative mouse, the host-capture mouse lock
  engages only while that source is active.
  - `cerf/host/pointer_router.{h,cpp}`, `cerf/host/pointer_widget.{h,cpp}`

- **`HostInputCapture`** - the low-level keyboard hook and capture toggle, so
  the guest receives the keys that the host shell normally takes. It forwards
  to `KeyboardInput` and synthesizes Ctrl-Alt-Del. Installation and removal
  happen on the UI thread. - `cerf/host/host_input_capture.{h,cpp}`

- **`HostStatusBar`** - the bottom status bar. It renders the ordered widget
  set of `HostWidgetRegistry` (icons + per-icon tooltips, left-click →
  primary action, right-click → declarative popup). The capture/lock
  indicator is itself one such host-owned widget.
  - `cerf/host/host_status_bar.{h,cpp}`

- **`HostWidget` / `HostWidgetRegistry`** - the status-bar + Actions-menu
  widget framework. `HostWidget` is an abstract, **non-`Service`** interface,
  so a `Peripheral`, which already derives `Service`, implements it with no
  diamond. Any service implements it to declare a host-UI presence: a custom
  GDI icon, tooltip, left-click action, declarative right-click menu
  (replicated into the Actions menu), hot-path-safe RX/TX activity dots, an
  `IsEnabled()` grayscale seam, and a `WidgetGroup` order key (the terminal
  `InputControl` group pins rightmost). Implementers self-register with
  `HostWidgetRegistry` from `OnReady`, the same way peripherals self-register
  with `PeripheralDispatcher`. `HostStatusBar` renders the ordered set, and
  concretes obey the three-tree rule (`cerf/socs|boards|peripherals/`). Use
  this framework whenever a peripheral or board has user-visible state
  (RX/TX, enabled/disabled) or a configuration/toggle surface.
  - `cerf/host/host_widget*.{h,cpp}`

- **`HostScreenshot`** - screenshot + clipboard capture of the live guest
  surface (via `HostCanvas::CaptureGuestSurface`, 1:1).
  - `cerf/host/host_screenshot.{h,cpp}`

## TraceManager

The always-built developer facility that attaches in-host C++ handlers to guest
PC addresses and to per-`Run` iteration ticks. Bug-specific diagnostics
therefore never pollute permanent code. When no traces are registered, hot
paths have zero
overhead (empty-container short-circuit). Hook surfaces: `OnPc` /
`OnPcFiltered` (per-instruction, where the filtered form takes a fire-time
process predicate), compiled in every configuration, and `OnRunLoopIter`
(dev-only). Handlers read guest memory through `TraceContext::ReadVa8 / 16 / 32`
(`GuestEngine::PeekGuestVa`), with no MMU side effects.

[agent_docs/debugging.md](debugging.md) § TraceManager covers usage: how to
pick a hook VA, per-process filters, when to trace instead of `LOG`, and how
to add a device trace file.

- `cerf/tracing/trace_manager.{h,cpp}`, `Trace` log channel.

## Device-specific trace files

`cerf/tracing/<bundle>/*.cpp` - one subdirectory per device bundle.
Each file is a small `Service` whose `OnReady` calls
`TraceManager::RegisterForBundle(<expected_crc32>, register_fn)`. The
closure runs if and only if the CRC32 of the live bundle matches. On a
mismatch the file silently does nothing at runtime. A header in that
directory declares the constant that every trace file in it uses
(`constexpr uint32_t k<Bundle>Crc32 = ...;`). The location of the header
decides whether git keeps it:

- **`<bundle>/nkdbg/bundle.h` is the only committed CRC header.** Two
  conditions admit a bundle to this form. The bundle ships a production
  kernel-debug hook under `nkdbg/`, and its ROM is a permanent board
  image.
- **Every other CRC header in `<bundle>/` is gitignored**, with the rest
  of the personal trace scaffolding. The convention names it `bundle.h`.
  A bundle with no `nkdbg/` hook has only this form, so its CRC stays out
  of the repo. A temporary or work-in-progress ROM is always this form.
  When one directory holds both headers, the ignored header includes
  `nkdbg/bundle.h` and does not restate the constant.

`TraceManager::OnReady` computes the bundle CRC32 over the
concatenated `RomParserService::Loaded()[i].raw` bytes in load order. On
the first boot of a new bundle, the log line `[TRACE] bundle CRC32 = 0xXXXX`
gives you the value to paste into that header.

`build.ps1 -Mode production` excludes the per-device trace files from the
build with a `<ClCompile Remove="tracing\*\**\*.cpp">` rule in
`cerf/cerf.vcxproj`. It then re-includes `tracing\*\nkdbg\*.cpp`, so the
kernel-debug hooks stay in production builds. The framework
(`cerf/tracing/trace_manager.{h,cpp}`) stays compiled. With no registered
traces, every hook is a single empty-container check.

**CRC32 / bundle gating is diagnostics-only - never runtime behavior.**
Production builds strip this per-device trace tree. Any emulation or board
behavior behind a `RegisterForBundle` / bundle-CRC gate therefore compiles
OUT of the production binary. It works in a dev build and is silently dead
for every user, and no error points at the absence. A CRC also matches ONE
exact ROM image, never a class. A board has many ROMs (revisions, regions,
generations, future user dumps), so CRC-gated behavior needs an unbounded
checksum list, and any unseen ROM gets nothing. Behavior that must hold for
a class of ROMs uses a ROM-content fingerprint that generalizes, the way
`BoardContext` does. CRC/bundle gating stays in diagnostics, where its
single-image, dev-only nature is exactly correct.

The one production-built CRC-gated exception is the kernel-debug (`nkdbg/`)
hooks. They are OBSERVATION-ONLY: they read guest debug text and emit it to
the log and HwScreen, and they never alter emulation or board behavior. They
also fail benignly: a CRC mismatch installs no hook, which costs only absent
debug output, never a device that misbehaves. Anything that changes how the
guest runs stays out of CRC gates.

- `cerf/tracing/<bundle>/`

## Kernel debug output

`KernelDebugSink` (`cerf/tracing/kernel_debug_sink.{h,cpp}`) is the single
funnel for guest OS debug text. Every producer routes finished lines to it:
the TX of a live SoC/board UART or serial peripheral, and a hook on a nulled
OEM debug sink (`cerf/tracing/<bundle>/nkdbg/`). It emits each line to the
`Nkdbg` log channel (`[NKDBG]`) and to the `HwScreen` debug console.

- `EmitLine(line, source, to_screen)` - the output primitive. `source` is an
  optional tag (for example `"UART1"`).
- `EmitChar(ch, buf, …)` - the common CRLF / hex-escape / cap accumulator over a
  caller-owned buffer (concurrent producers never share state).
- `EmitWideStringAt(ctx, va, …)` - read a guest wide string and emit it.

A UART/serial peripheral never open-codes `LOG` + `HwScreen::AddLine`. It calls
the sink. Register-access logging stays on its own SoC channel (for example
`SocUart`) and is gated like any other channel. Only the assembled debug line
is `Nkdbg`.

- `cerf/tracing/kernel_debug_sink.{h,cpp}`, `Nkdbg` log channel

## Bundled device tree

`bundled/devices/<name>/` is the input that CERF reads at boot:

- A Windows CE ROM image, `*.nb0` or `*.bin`. CERF takes whichever file
  is present. The filename does not matter.
- `cerf.json` - the optional per-device configuration. Every field is optional,
  and `cerf.exe` runs without the file. The file is required in one case only:
  a multi-partition / multi-file bundle, for example a ROM plus a separate
  EEPROM image present together. The `rom` block then names which file boots
  and which file is data, so CERF does not guess. Everything else in the file
  is a user convenience. The `meta` block is launcher-only metadata (display
  name, board, SoC, OS, year). The `board` / `network` / `rom` overrides let a
  user pre-bake options that the launcher or the CLI otherwise passes each
  time (a custom screen resolution on boards that support one or for a
  guest-additions boot, a force-flipped flag). When the file is absent, CERF
  uses `DeviceConfig` defaults plus CLI overrides.

`./launcher` syncs `bundled/devices/`. It downloads the public manifest and
installs selected bundles.

Git ignores the downloaded bundle directories and the local `manifest.json`.
Only those are copied to the release directory. Users run `launcher` locally.
Never run `launcher` on your own.

For IDA debugging, `tools/extract_bundles.py` decomposes the same `.nb0` /
`.bin` offline into `references/extracted-roms/<dev>/<rom>/`. The script runs
`references/extract-wince-rom` against each ROM and copies in any matching
PDBs. That tree is gitignored. CERF does not consume it at runtime. It serves
IDA / static analysis only - see `agent_docs/debugging.md` § IDA discipline.

The `CopyBundledFiles` MSBuild target mirrors `bundled/**/*` into
`build/<config>/Win32/**` at build time. The copy is incremental and never
deletes destination files that are absent from the source set.

CERF uses `bundled/devices` locally, because the build syncs it into
`build\release\win32\devices`. Regular users have the launcher inside the
build directory and sync the devices folder there.

## CE Apps - CERF-built CE binaries

The `ce_apps/<name>/` directories build small Windows CE EXEs and DLLs
against the per-CE-era SDKs in `references/WindowsCE-Build-Tools/`
(`ce3-oak` … `ce7-oak`), per guest architecture. Each
directory has a `main.c` and a one-line `build.ps1` that delegates to
`tools/build_ce_app.ps1`. After msbuild succeeds, the top-level `build.ps1`
walks every `ce_apps/*/build.ps1`. Outputs land at
`build/<Config>/Win32/ce_apps/<arch>/`. This tree hosts the `cerf_guest`
guest-additions display driver next to sample binaries. It is the home
for any CERF-built CE binary.
