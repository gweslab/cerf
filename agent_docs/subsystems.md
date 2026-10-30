# CERF Subsystems

The host-side subsystem set is small. CE-side binaries (kernel, OAL, drivers,
userspace) run unmodified as guest code through the JIT. They are not host
subsystems. This page lists what CERF itself owns.

## Libraries and frontends

CERF splits into libraries and a frontend:

- **libCerfEngine** (submodule) - the JIT.
- **libCerfCore** (submodule) - the emulation core and the seams that a
  frontend implements.
- **cerf-qt** - the frontend, one Qt application. It has a desktop form and an
  Android form. The root of `cerf-qt/` holds the code that both forms compile.
  `desktop/` and `mobile/` hold the code of one form.

The core never includes frontend code. A frontend includes only public core
headers. When the core needs an action or an answer from the frontend, it
declares a seam service, for example `UserAlert` or `DeviceSelection`. A seam
is required unless the core resolves it with `TryGet<T>()`.

The core receives host input as events with their real timing and order. Some
host platforms, input devices or UI toolkits do not report the full timing. For
example, a key can arrive with no press time. The frontend of that platform
corrects the event before the core receives it. A correction for one input
source never goes into a core path that every host and every source shares.

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
- **Misuse halts the instance with the types named**: two `ShouldRegister`
  true for one Base, a required slot with no winner, or a
  `ShouldRegister`↔`Get` cycle. You need no defensive check around `Get<>`.
  A derived locator handles the misuse in its `RaiseLocatorError`, at the
  failing call, so the crash report holds the stack of that call.
- **`ShouldRegister()`** can call `Get<>`/`TryGet<>` through the same lazy
  path. The idiom is `emu_.Get<BoardContext>().GetSocId() == SocId::X`.
- **`Get<Foo>()` resolves the `Base` slot first when
  `REGISTER_SERVICE_AS(Foo, Base)` registers `Foo`.**
- **Any thread can call `Get<>` at any time.** A thread that needs a slot
  while another thread resolves it waits, then gets the winner of that slot.
  Each slot resolves once.
- **The Android frontend boots the emulator on a boot thread.** Qt binds a
  `QObject` service to the thread that creates it. As a result, the GUI thread
  creates the services. A boot thread runs the resolution sweep and the
  readiness sweep, and starts the guest. The emulator window opens after the
  readiness sweep and before the guest starts. A job that a service posts to the
  window before that time runs after the window opens.
- **On Android, every device instance shares the GUI thread with the
  manager.** Device code opens a nested event loop only through
  `NestedEventLoops`. `QtEmulatorRun` holds the exit of the instance until every
  such loop returns. The owner destroys the instance on that exit, so no frame
  of the instance is on the stack then.
- **A thread that `OnReady` starts gets its services from `OnReady`.** `Get<>`
  runs `OnReady` on the thread that asks first, also while the boot sweep runs
  on the boot thread. A thread that asks for a service that is not ready yet
  runs its setup beside the boot sweep. Two setups that touch the same state
  then race. Resolve every service that the thread uses before you start it.
- **The locator is the `libservicelocator` submodule.**

- `libCerfCore/include/cerfcore/core/cerf_emulator.h`, `libCerfCore/include/cerfcore/core/service.h`,
  `libservicelocator/include/servicelocator/`

## Guest CPU JIT

Guest code runs through a block JIT. Every ROM binary is the original guest
code, translated to host x86 on the fly. This covers
`nk.exe` / `coredll.dll` / `gwes.exe` / `filesys.exe` / `device.exe` /
userspace EXEs / driver DLLs. `JitRunner` drives an abstract `GuestEngine`
service. The concrete engine implements it for the CPU architecture of the
board, and `BoardContext::GetCpuArch()` selects it. Per-SoC variation lives
in per-core strategy services that `GetSocId()` selects. These reach the
engine through its host interfaces. Per-SoC variation is never an
`if (soc == X)` branch in the engine.

- `libCerfEngine/`, `libCerfCore/src/execution/`, [agent_docs/jit.md](jit.md)
- the guest cycle clock every timer derives from:
  [agent_docs/timers_clocks.md](timers_clocks.md)

## Per-chip / per-board / per-part strategies

CERF splits per-impl code across three orthogonal trees. The nature of the
implemented thing selects the tree.

### `libCerfCore/src/socs/<chip>/` - on-die silicon

Each SoC family has one directory. The directory contains:

- per-peripheral `<chip>_*.cpp` - UART, INTC, GPIO, RTC, timer, watchdog,
  clock/power, memory controller, LCD controller, NAND controller, IIS,
  and more.

The `ShouldRegister` of a concrete returns
`emu_.Get<BoardContext>().GetSocId() == SocId::X`. Chip-layer code
never knows its board. It knows only its chip.

The VA→PA placement map (`PageTableBuilder`) does not live here. The core
CPU strategies (`ArmCoprocProvider`) split on a different axis. VA→PA placement
is a BSP/board choice, because the OEMAddressTable differs per board. Its
concretes live under `libCerfCore/src/boards/<family>/`, and `GetBoardFamilyId()`
selects them.

A core strategy is a CPU-arch property that
is identical across every board on that core. Its concretes live under
`libCerfCore/src/cpu/<core>/`, and `GetSocId()` selects them. A core strategy that a board
family gates leaves every other family on that SoC with no winner.

The static facts of a core are data, not a strategy. ID register values and
instruction-set capabilities live in the `cpu_configs` rows of `db.json`.

### `libCerfCore/src/boards/<family>/` - one board family

Each board family has one directory. The directory and its files carry the
family name, never the name of one member. The directory contains:

- `<family>_context.cpp` - the concrete `BoardContext` impl
- `<family>_page_table_builder.cpp` - the `PageTableBuilder` impl of the
  family: the BSP OEMAddressTable VA→PA map, the DRAM/flash backed regions,
  and the bootloader-handoff SP. ROM placement and pre-MMU boot use it
- board-only virtual peripherals - host-emulator notification channels,
  virtual DMA transports, folder-sharing helpers. These peripherals exist
  only because the BSP of the board expects the emulator to provide them
- BSP-specific configuration writers (for example `<family>_bsp_args.cpp`,
  which fills a DRAM struct that the BSP reads on boot)

The `ShouldRegister` of a concrete returns
`emu_.Get<BoardContext>().GetBoardFamilyId() == BoardFamilyId::X`.

### `libCerfCore/src/peripherals/<vendor>_<part>/` - off-chip silicon shared across boards

Each off-chip IC family has one directory.

The `ShouldRegister` of a concrete compares against a family list:

    auto f = emu_.Get<BoardContext>().GetBoardFamilyId();
    return f == BoardFamilyId::X || f == BoardFamilyId::Y;

The list grows when a new family adopts the same part. Do not duplicate the
part file. The part directory is the single source of truth for what the IC
does.

The `libCerfCore/src/peripherals/` root (not under any vendor subdir) also holds
the abstract `Peripheral` base (`peripheral_base.{h,cpp}`) and the
MMIO router (`peripheral_dispatcher.{h,cpp}`). All peripheral-domain
code - framework and concretes - lives in this one tree.

### Trees vs bases

Abstract bases (`BoardContext`, `PageTableBuilder`,
`Peripheral`) live next to their consumers (`libCerfCore/src/boards/`, `libCerfCore/src/core/`,
`libCerfCore/src/cpu/`, `libCerfCore/src/peripherals/`), not under any per-impl tree.

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

- `libCerfCore/src/socs/`, `libCerfCore/src/boards/`, `libCerfCore/src/peripherals/`

## PCMCIA

16-bit PC Card emulation, split framework/controller/card:

- **`PcmciaCard`** (`libCerfCore/src/peripherals/pcmcia/pcmcia_card.h`) - the abstract
  card. Cards are plain objects (NOT Services).
  `PcmciaCardCatalog::Create()` creates a card, and its slot owns it. One
  type can occupy two slots at once. Concretes:
  `libCerfCore/src/peripherals/realtek_rtl8019/` (NE2000 NIC),
  `libCerfCore/src/peripherals/compactflash/` (PC Card ATA + FAT32 image builder +
  insert entry), `libCerfCore/src/peripherals/serial_pccard/` (16550 serial /
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
  card lifetime and bus serialization. It IS the HostWidget, and it exposes
  the socket as one slot control. The controller that owns the
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
  registry of insertable card types. A new card type is one `PcmciaCard`
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
`compaq_ipaq_h3000_pcmcia_sleeve.cpp`, `askey_pc3xx_pcmcia.cpp`.

- `libCerfCore/src/peripherals/pcmcia/`

## Serial

The serial stack that any UART can use. The same endpoints serve an
on-SoC UART and a serial PC card. A board therefore gains ActiveSync /
dial-up through one interface. The stack splits into line and personality:

- **`SerialLine`** (`libCerfCore/src/peripherals/serial/serial_line.h`) - the abstract
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
  its insert entries. A modem attached to the serial port of a board therefore
  looks like an inserted card. The UART peripheral owns it. It is not a
  Service.
- `libCerfCore/src/peripherals/serial_pccard/` holds ONLY the PC-card consumer. The
  framework named here is board-neutral and lives in
  `libCerfCore/src/peripherals/serial/`.

To wire the stock UART of a board, implement `SerialLine` on the UART
peripheral (RX path + an RX interrupt + baud from its divisor + modem
status on whatever pins the board wires). Own a `SerialCradle`. Supply a
per-board seam that names the modem pins. Take those pin numbers from the
serial driver of the board. Never guess them.

- `libCerfCore/src/peripherals/serial/`

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

**The result of a reset must not depend on the order of the reset
listeners.** The reset line holds every unit in reset at the same time, but
the listeners run one after another. A write from one reset listener into
another unit therefore reaches that unit before its own reset or after it.
When the two results differ, the write goes in a release listener. Examples
are a new clock rate, a pin level that the other unit latches, and a value
that a skipped bootloader leaves in another unit. Release listeners run after
every reset listener and after the cold boot.

- `libCerfCore/include/cerfcore/socs/guest_cpu_reset.h`, `libCerfCore/src/socs/guest_cpu_reset.cpp`

**`GuestColdBoot`** implements hard reset (cold boot). At reset
delivery it wipes every volatile RAM region (flash survives), replays
registered boot-time guest-RAM writes in registration order, and
flushes the translation cache. Every service that writes guest RAM
during `OnReady` (ROM placement, BSP_ARGS blocks, image injection)
MUST register a replay. When the computation that produces the bytes
allocates and must not run again, register a byte-exact `RecordPatch`
instead. Without one of the two, the bytes of that service are silently
absent after every hard reset on that board.

- `libCerfCore/include/cerfcore/boot/guest_cold_boot.h`, `libCerfCore/src/boot/guest_cold_boot.cpp`

## Host window & presentation

This section covers the emulator window of a frontend, its drawable area, and
the render and input plumbing that connects the host UI to the guest. All are
`Service`s. The
renderer, touch, and keyboard pieces are abstract bases with
per-SoC/per-board concretes (strategy pattern, selected by `BoardContext`).

- **`FrontendWindow`** - the emulator window seam of cerf-qt. It
  switches the canvas tab, follows the guest size, and runs jobs on the UI
  thread. `Tab` is an alias of the core `CanvasTab` enum,
  so core configuration can name the startup tab with no dependency on the
  host layer. Its guest-surface dimensions are atomic, so any thread can read
  them. The SoC LCD service calls
  `HostPresentation::PanelEnabled()` on the guest panel-enable edge, and
  `FrontendHostPresentation` forwards it to `FrontendWindow::OnLcdEnabled()`.
  The call carries no dimensions. The call tells the frontend to read the
  new size from `FrameRenderer::PresentedSize`.

  The window of each frontend form is a service of its own type. Code of
  that form resolves the window by that type. A private subclass of
  `FrontendWindowAdapter` fills the `FrontendWindow` slot. That subclass
  forwards each call to the window service.
  - `cerf-qt/frontend_window.h`, `cerf-qt/frontend_window_adapter.{h,cpp}`;
    desktop `cerf-qt/desktop/qt_main_window.{h,cpp}`, Android
    `cerf-qt/mobile/mobile_emulator_window.{h,cpp}`

- **The panel code is the only authority on the guest resolution. Two
  states sit outside it, and one board fact serves both.** The guest signals
  its resolution to the LCD peripheral, and the window follows that edge.
  Before the guest runs, no such signal exists, and the window already needs
  a size. Guest additions replace the display driver, so they need a size of
  their own.

  A board declares its panel size in the board database, and CERF opens the
  window at that size. When the guest signals the same size, the user sees
  no window resize. A panel that reports a different size wins.

  When the user sets no guest-additions resolution override, guest additions
  take that same board fact. The manager resolves that order too.

  **A default that is too large breaks many guests.** A board whose panel the
  user can change therefore declares the size it uses by default. When no single
  size is right for the board, it declares none, and the window opens at the
  CERF default.

- **The Android system bars** - the Android emulator window runs in full screen
  with the system bars hidden. Its floating bar fades when nobody uses it. A
  swipe that brings back the system bars also brings back the floating bar.
  When the floating bar fades, the system bars hide again.

  **Qt hides the bars in the mode that reports no swipe to the app.**
  `AndroidSystemBars` switches the hidden bars to the mode that reports the swipe.
  - `cerf-qt/mobile/android_system_bars.{h,cpp}`,
    `cerf-qt/mobile/android/src/cx/cerf/SystemBarsWatch.java`

- **The canvas** - the drawable area of the emulator window. It implements
  `CanvasInputHost` and owns the one transform from host pixels to
  guest-surface coordinates (`HostToGuest`). As a result, taps land on the
  rendered image. On the first presented guest frame, `CanvasTabs` switches
  to the framebuffer tab, unless the user already picked a tab.
  - desktop `cerf-qt/desktop/qt_canvas.{h,cpp}`, Android
    `cerf-qt/mobile/guest_surface.{h,cpp}`

- **`FrameRenderer`** (abstract) - one producer of guest frames.
  `RenderInto(dib_bgra32, w, h)` fills a BGRA32 surface. `PresentedSize(w, h)`
  gives the extent of the image that this producer renders. The extent is
  already in presented orientation, so a renderer that rotates the image
  reports the swapped extent.

  **`PresentedSize` is the only authority on the panel-enable edge.**
  `HostPresentation::PanelEnabled()` carries no dimensions. The frontend posts
  it to the UI thread, and the UI thread reads the size through `PresentedSize`. A
  peripheral must never pass its own dimensions to the host. A renderer can
  draw at a different extent than the panel timing. If a peripheral passes its
  own dimensions, the window size disagrees with the image.

  The size read stays on the UI thread by construction. A publisher usually
  reaches `PanelEnabled()` with its own peripheral lock held, and
  `PresentedSize` goes back into that same peripheral. A read on the
  publishing thread therefore re-locks a non-recursive mutex. That wedges the
  JIT thread and the UI thread together.

  `PresentedSize` is not the only source of the guest-surface size.
  `FrontendWindow::SetGuestSurfaceSize` is the single entry point, and the
  panel-enable edge is only one of its callers.
  `FrontendWindow::SetGuestResolution` calls it for a guest re-mode and for
  the resolution dialog. `GuestAutoResize::OnUserResizeEnd` reaches it
  through that same path, and is not a separate setter.
  `Hibernation::RestorePresentation` reaches it through
  `HostPresentation::RestoreSurfaceSize` with the size from the state image.
  As a result, a restore installs a surface size that `PresentedSize` never
  produced.

  Three slots build on this base:

  - **`PanelFrameRenderer`** - the physical panel scanout of the board. Every
    hardware renderer registers here. Its `ShouldRegister` gates on hardware
    presence only (board, SoC or part). It never gates on guest additions.
    Concretes live with the hardware that produces the frame: per-SoC
    LCD/DSS/IPU renderers under `libCerfCore/src/socs/<chip>/`, board renderers under
    `libCerfCore/src/boards/<family>/`, off-chip display parts under
    `libCerfCore/src/peripherals/<vendor>_<part>/`.
  - **`GuestAdditionsFrameRenderer`** - the guest-additions virtual
    framebuffer under `libCerfCore/src/peripherals/cerf_virt/`. It wins only on a
    `--guest-additions` run.
  - **`FrameRenderer`** itself - the presented surface. It has one candidate,
    **`PresentedFrameRenderer`**, and the canvas of each frontend binds it.

  **`PresentedFrameRenderer`** is an ordered stack of the two layers above.
  The panel layer renders under the guest-additions layer. A splash that the
  bootloader or the kernel draws therefore stays visible until the
  guest-additions display driver renders its first frame. The boot animation
  of CERF is only the placeholder while the guest renders nothing.

  The compositor fits a layer of another size to the surface, keeps its aspect
  ratio, and centers it. It never crops a layer. The compositor enlarges a
  smaller layer by the largest integer factor that fits, with nearest-neighbor
  sampling. It reduces a layer that is larger on either axis. Each output
  pixel is then the average of the source pixels under it.

  The layers are opaque, and the compositor skips each covered layer. The
  compositor must not blend the layers per pixel. The guest-additions surface
  has areas that are legitimately black, and a blend makes the panel layer
  visible through them.

  The layer that covers the surface renders directly into the target DIB, so
  it costs no copy. The scratch buffer and the scaled copy occur only while
  the compositor presents a layer of another size.

  The compositor sends `RearmContentLatch` to every layer, so a guest reset
  rearms all of them.

  To add a layer, register it on its own role slot. Then put the layer in the
  order of the compositor.
  - `libCerfCore/include/cerfcore/host/frame_renderer.h`, `panel_frame_renderer.h`,
    `guest_additions_frame_renderer.h`, `cerf-qt/presented_frame_renderer.cpp`

- **`HwScreen`** - the hardware text console behind the `Tab::Hw` tab. It is
  the bounded text-mode RX/TX line buffer for guest UART / OEM-debug output
  and for the notices of CERF itself (power events, save/restore progress).
  `AddLine` appends a line, and `Snapshot` copies the lines for a frontend.
  `HwScreenRenderer` draws the scrolled log over the `BootBar` through the
  `Painter` of the frontend.
  - `libCerfCore/include/cerfcore/host/hw_screen.h`, `libCerfCore/src/host/hw_screen.cpp`,
    `cerf-qt/hw_screen_renderer.{h,cpp}`

- **`NotificationStack`** is the card stack over every canvas tab, and it takes
  only notices that interrupt the user's workflow, never routine events.

- **`BootScreen`** - the CERF-logo boot animation behind the `Tab::Boot` tab,
  plus the `BootBar`. The 60 Hz present loop drives it in time, with no
  thread. `Restart` (guest reboot / deep-sleep wake) and
  `OnFramebufferLatched` are its cross-thread control hooks.
  - `cerf-qt/boot_screen.{h,cpp}`

- **`BootBar`** - the bottom CPU-activity bar shared by the Boot Screen and
  Hardware Screen tabs. It is a strip that scrolls. The host animation clock
  advances it, so it freezes when emulation is paused.
  - `cerf-qt/boot_bar.{h,cpp}`

- **`TouchInput`** (abstract) - takes host pen events in guest-surface
  coordinates. The touch peripheral concrete of the board converts them into
  guest pen samples. The concretes live under `libCerfCore/src/boards/<family>/`.
  - `libCerfCore/include/cerfcore/host/touch_input.h`

- **Off-screen bezel touch buttons are physical, never framebuffer-drawn.**
  Some resistive-panel boards (Jornada 720, Casio Toricomail) print soft
  buttons on the bezel, over the digitizer and outside the LCD area. The
  guest does not render them. They are extra areas of the same touch panel,
  in a raw-ADC band past the screen's active range. The board maps its screen
  to a raw sub-range (a per-board seam) and reserves the rest of the range for
  the buttons. Each of these buttons is an action of the `DeviceButtons` service
  of the board. The HUD of the board shows it. The action sends a synthetic pen
  tap with a hold at the raw position of its zone, because no on-screen pixel
  maps to the zone. The guest driver resolves the zone-to-key mapping and its own
  calibration. CERF models only the panel geometry, never the guest's button
  table.

- **`ButtonRow`** - the special keys of the active keyboard source on the
  Android strip. The desktop status bar shows no keys. The HUD carries the keys
  of the device.

  **The Android strip shows special keys only while the soft keyboard is open.**
  It shows the keys that the board does not rename and that the soft keyboard
  lacks. The soft keyboard has Enter, so the strip never shows it. A key that the
  board renames, for example LSK, belongs on the HUD.

  **A special key stays down for as long as the user presses its button.** The
  Android strip scrolls, so it sends the key-down when the press becomes a tap.
  It sends the key-up when the key was down for as long as the finger held the
  button. A press held for one second latches the key. The key then stays down
  until the next tap on its button, or until the strip hides the key.
  - `cerf-qt/button_row.h`

- **The HUD** - the device buttons and d-pads that the frontend draws around the
  framebuffer. `libCerfCore/huds.json` holds the presets.

  **A HUD press is a press on the stock keyboard of the board.**
  `KeyboardRouter::OnStockKey` sends it to the stock keyboard, also while the
  guest-additions keyboard is active. A HUD key is a key of the device, for
  example a key on the Fn layer of the Device Emulator keypad. The
  guest-additions keyboard sends raw virtual keys and has no such layer. A HUD
  button shows as held while the HUD or the host keyboard holds its keys.

  **A HUD key changes its face on a layer only where the keyboard map of the board
  binds it on that layer.** While a key that holds a layer is down, such a HUD key
  shows the face that the HUD preset gives it for that layer. Without that face, it
  shows the label of the binding. A HUD key with no label or icon of its own shows the label of its
  binding on the base layer. On the desktop, a HUD key that the map renames shows the name
  of its host key in small text in a corner.

  **A HUD action button runs one action of the `DeviceButtons` service of the
  board.** The whole action runs on one press.

  **On the desktop, the fit modes fit the framebuffer and its HUD as one box.**
  Every host-to-guest point maps through that fit. The HUD keeps the size of its
  screen in guest pixels, so a larger guest resolution does not enlarge it.

  **On Android, the HUD sits at the sides of the safe zone.** A panel names a
  side of the framebuffer. The panel goes to the canvas side that this
  framebuffer side faces after the rotation. Each panel spans its whole side.
  When that makes a panel longer than on the desktop, the panel also gets deeper
  by the same factor. It never takes more than the space that the framebuffer
  leaves free.

  While the canvas, seen from the turned framebuffer, is taller than wide, a
  panel uses its portrait form when the preset gives one. The framebuffer fits, pans and zooms in the rest of the
  canvas. The HUD band takes every touch inside it that no notification card covers.
  - `cerf-qt/hud_selection.h`, `cerf-qt/hud_controls.h`, `cerf-qt/hud_renderer.h`,
    `cerf-qt/view_presentation.h`, `libCerfCore/include/cerfcore/host/device_buttons.h`

- **`ViewRotation`** - turns the presented framebuffer by quarter turns. The guest
  sees no change. The HUD panels, the host-to-guest point map and the relative
  mouse deltas turn with the frame. The rotation lasts for the session only.
  - `cerf-qt/view_rotation.h`

- **`KeyboardInput`** (abstract) - one keyboard source: `OnHostKey(vk, key_up)`
  plus `SourceName` / `SourcePriority` / `SourceReady`. Concretes self-register
  with `KeyboardRouter`. They are the keyboard of a board under
  `libCerfCore/src/boards/<family>/` and the guest-additions keyboard under
  `libCerfCore/src/peripherals/cerf_virt/`.
  - `libCerfCore/include/cerfcore/host/keyboard_input.h`

- **`KeyboardRouter`** - the keyboard-source registry and host-key funnel.
  `KeyboardInput` concretes self-register from `OnReady`. The router forwards
  host keys to the single active source.

  **A key belongs to the source that receives its key-down.** That source
  receives the key-up of the key, also after the active source changes. A
  key-down of a key that another source holds releases the key on that source
  first. A key-up of a key that no source holds reaches no source.

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
  - `libCerfCore/include/cerfcore/host/keyboard_router.h`, `libCerfCore/src/host/keyboard_router.cpp`

- **`PointerRouter` / `PointerWidget`** - the pointer-source registry and
  host-mouse funnel. It mirrors `KeyboardRouter`. Pointing-device sources
  (the touch / mouse of a board, the guest-additions absolute pointer)
  self-register. The frontend sends host mouse messages to the single
  active source. The router selects by the same ready-then-priority rule as
  `KeyboardRouter`, and it carries the same `RearmAutoSelect` /
  `ReevaluateAuto` pair.

  **A pen or a mouse button that is down stays with the source that received
  the press.** This holds also after the active source changes. A host mouse
  event that reports the button up releases it on that source.

  When more than one is registered, the `PointerWidget` status-bar widget
  switches the active source and keeps the choice across hibernation. Some
  apps (calibrators) read the stock touch/mouse stream directly. On a board
  whose stock pointer is a relative mouse, the host-capture mouse lock
  engages only while that source is active.
  - `libCerfCore/include/cerfcore/host/pointer_router.h`, `libCerfCore/src/host/pointer_router.cpp`, `libCerfCore/src/host/pointer_widget.cpp`

- **`InputCapture`** - the capture toggle, so the guest receives the keys
  that the host shell normally takes. It forwards to `KeyboardInput` and
  synthesizes Ctrl-Alt-Del. Each frontend feeds it host keys. On Windows, the
  desktop frontend takes them from `LowLevelKeyboardHook` and installs that
  hook on the UI thread.
  - `cerf-qt/input_capture.{h,cpp}`, `cerf-qt/desktop/qt_input_capture_windows.cpp`

- **`StatusBar`** - the bottom status bar. It lays out and paints the ordered
  widget set of `HostWidgetRegistry` (icons and per-icon tooltips), and it
  sends each mouse click to its widget. The capture/lock indicator is itself
  one such host-owned widget. The window, the tooltips and the timer of the
  bar belong to the frontend.
  - `cerf-qt/status_bar.{h,cpp}`, `cerf-qt/desktop/qt_status_bar.{h,cpp}`, `cerf-qt/mobile/mobile_widget_bar.{h,cpp}`

- **`HostWidget` / `HostWidgetRegistry`** - the live configuration surface of
  a peripheral or a board feature. `HostWidget` is an abstract,
  **non-`Service`** interface, so a `Peripheral`, which already derives
  `Service`, implements it with no diamond. A widget declares typed metadata
  only: its state and its controls. A slot control names the inserted item
  and every insertable item by a stable id. A widget draws nothing and builds
  no menu. Each frontend renders the metadata in its own form.

  Implementers self-register with `HostWidgetRegistry` from `OnReady`, the
  same way peripherals self-register with `PeripheralDispatcher`. Concretes
  obey the three-tree rule (`libCerfCore/src/socs|boards|peripherals/`). Use this
  framework whenever a peripheral or board has user-visible state (RX/TX,
  enabled/disabled) or a configuration/toggle surface.
  - `libCerfCore/include/cerfcore/host/host_widget*.h`, `libCerfCore/src/host/host_widget_registry.cpp`

- **`Screenshots`** - screenshot + clipboard capture of the live guest
  surface (via `FrontendWindow::CaptureGuestSurface`, 1:1). The
  `ImageExporter` seam of the frontend writes the PNG and fills the
  clipboard.
  - `cerf-qt/screenshots.{h,cpp}`

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

- `libCerfCore/src/tracing/trace_manager.{h,cpp}`, `Trace` log channel.

## Device-specific trace files

`libCerfCore/src/tracing/<bundle>/*.cpp` - one subdirectory per device bundle.
Each file is a small `Service` whose `OnReady` calls
`TraceManager::RegisterForBundle(<expected_crc32>, register_fn)`. The
closure runs if and only if the CRC32 of the live bundle matches. On a
mismatch the file silently does nothing at runtime. A header in that
directory declares the constant that every trace file in it uses
(`constexpr uint32_t k<Bundle>Crc32 = ...;`). The convention names it
`bundle.h`.

`TraceManager::OnReady` computes the bundle CRC32 over the
concatenated `RomParserService::Loaded()[i].raw` bytes in load order. On
the first boot of a new bundle, the log line `[TRACE] bundle CRC32 = 0xXXXX`
gives you the value to paste into that header.

`build.py --mode production` builds libCerfCore with
`CERFCORE_DEVICE_TRACES` off. The build then excludes every per-device trace
file. The framework (`libCerfCore/src/tracing/trace_manager.{h,cpp}`)
stays compiled.

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

- `libCerfCore/src/tracing/<bundle>/`

## Kernel debug output

`KernelDebugSink` (`libCerfCore/src/tracing/kernel_debug_sink.{h,cpp}`) is the single
funnel for guest OS debug text. A live SoC/board UART or serial peripheral
routes the finished lines of its TX to it. It emits each line to the
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

- `libCerfCore/src/tracing/kernel_debug_sink.{h,cpp}`, `Nkdbg` log channel

## Byte order

`libCerfCore/include/cerfcore/core/byte_order.h` and the `cerfengine/byte_order.h` header of
libCerfEngine hold the only code that reads and writes multi-byte values in a
byte buffer. Do not write a local shift-and-or or a local `Put32`.

## Bundled device tree

`bundled/devices/<name>/` is the input that CERF reads at boot:

- A Windows CE ROM image, `*.nb0` or `*.bin`. CERF takes whichever file
  is present. The filename does not matter.
- `cerf.json` - the optional per-device configuration. Every field is optional,
  and `cerf.exe` runs without the file. The file is required in one case only:
  a multi-partition / multi-file bundle, for example a ROM plus a separate
  EEPROM image present together. The `rom` block then names which file boots
  and which file is data, so CERF does not guess. Everything else in the file
  is a user convenience. The `meta` block is manager-only metadata (display
  name, board, SoC, OS, year). The `board` / `network` / `rom` overrides let a
  user pre-bake options that the manager or the CLI otherwise passes each
  time (a custom screen resolution on boards that support one or for a
  guest-additions boot, a force-flipped flag). When the file is absent, CERF
  uses `DeviceConfig` defaults plus CLI overrides.

Git ignores the bundle directories and the local `manifest.json` in
`bundled/devices/`.

For IDA debugging, `tools/extract_bundles.py` decomposes the same `.nb0` /
`.bin` offline into `references/extracted-roms/<dev>/<rom>/`. The script runs
`references/extract-wince-rom` against each ROM and copies in any matching
PDBs. That tree is gitignored. CERF does not consume it at runtime. It serves
IDA / static analysis only - see `agent_docs/debugging.md` § IDA discipline.

The `cerf-qt-bundled` CMake target mirrors `bundled/**/*` into the folder that
holds the frontend at build time. The copy is
incremental and never deletes destination files that are absent from the
source set.

## CE Apps - CERF-built CE binaries

The `ce_apps/<name>/` directories build small Windows CE EXEs and DLLs with
the eMbedded Visual C++ 4.0 toolchain and SDK in `third_party/wince`
(`docs/ce_apps_setup.md`), per guest architecture. A directory joins the build
when it has a `build.py`. Outputs land in `ce_apps/<arch>/` of the build output
directory of the host. This tree hosts the `cerf_guest`
guest-additions display driver next to sample binaries. It is the home
for any CERF-built CE binary.

On Linux the build runs the same toolchain through Wine. macOS cannot run it, so a macOS
build copies the CE apps of a Windows or Linux build (`build.py --ce-apps-from`).

The Android package (`build.py --android`) carries every CE app inside the APK. As a result,
the CE apps must exist before the frontend builds. A partial set of CE apps must not ship.
