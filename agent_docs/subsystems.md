# CERF Subsystems

The host-side subsystem set is small. CE-side binaries (kernel, OAL, drivers,
userspace) run unmodified as guest code through the JIT. They are not host
subsystems. This page lists what CERF itself owns.

## Libraries and frontends

CERF splits into libraries and frontends:

- **libCerfEngine** (submodule) - the JIT.
- **libCerfCore** (submodule) - the emulation core and the seams that a
  frontend implements.
- **cerf-qt** - one frontend, a Qt Quick application. Every host shows the
  same windows. The root of `cerf-qt/` holds the code that every host compiles.
  `desktop/` holds the code of the desktop hosts, and `android/` holds the code
  of Android.

The core never includes frontend code. A frontend includes only public core
headers. When the core needs an action or an answer from the frontend, it
declares a seam service, for example `UserAlert` or `DeviceSelection`.

**A frontend is one interaction seam among many. libCerfCore owns every behavior
that reads or drives the guest.** Examples are an analysis of the guest
framebuffer, a sequence of guest input, and the timers and the state of such a
feature. A frontend starts that behavior and shows it. When another frontend must
copy code to offer the same feature, that code belongs in a library.

**libCerfCore gives levers, typed state and events. A frontend decides how it
presents them.** The core never gives a menu, the label of a control, an icon, a
tooltip, a dialog or a layout.

**A guest event goes to the frontend as an event, never as a question.** The
frontend decides what it shows. It acts through core functions that work at any
time.

A core procedure that needs the decision of a person calls an abstract function of
its seam, for example `CalibrationHost::ApprovesCalibration`. The frontend owns the
words and the form of that decision. A question object that carries texts or text
ids is not such a function.

**Check every output of the core against three frontends:** cerf-qt, a 3D game,
and a factory automation with no screen. Each one must react to the output
without parsing English text.

**Text from the core to a person goes only through `NotificationStack` and
`UserAlert`.** The names of machine objects, input sources and card types are the
only other texts that the core gives a frontend.

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

- **Registration is one macro line per `.cpp`.** `REGISTER_SERVICE(Foo)`
  makes `Foo` resolvable only as `Foo`. `REGISTER_SERVICE_AS(Foo, Base)` makes
  `Foo` a candidate for the `Base` slot, also resolvable as `Foo` (the strategy
  pattern). `REGISTER_SERVICE_AS_FALLBACK(Foo, Base)` wins only if
  `ShouldRegister` returned true for no non-fallback candidate. Boot then
  constructs every candidate. Boot runs the `ShouldRegister` of each slot to pick the single
  winner. Boot then calls `EnsureReady` on **every** winner.
- **The `OnReady` of every winning service runs exactly once**, at boot. It
  runs whether or not anything ever calls `Get<>` for it. `OnReady` is also
  lazy. A first `Get<Dep>()` from inside your `OnReady` runs `Dep::OnReady`
  before it returns, so the graph self-orders on demand. Both paths guard
  with a mutex, so `OnReady` never runs twice. There is no init phase, no
  declared order, and no pre-warm step.
- **If no candidate won the slot, `Get<T>()` is fatal.** **`TryGet<T>()`**
  returns `nullptr` for an optional dependency.
- **Misuse halts the instance with the types named**: two `ShouldRegister`
  true for one Base, a required slot with no winner, or a
  `ShouldRegister`↔`Get` cycle. You need no defensive check around `Get<>`.
- **`ShouldRegister()`** can call `Get<>`/`TryGet<>` through the same lazy
  path.
- **`Get<Foo>()` resolves the `Base` slot first when
  `REGISTER_SERVICE_AS(Foo, Base)` registers `Foo`.**
- **Any thread can call `Get<>` at any time.** A thread that needs a slot
  while another thread resolves it waits, then gets the winner of that slot.
  Each slot resolves once.
- **The emulator window opens after the readiness sweep and before the guest
  starts.** A shown window can paint at once. That paint reads services whose
  `OnReady` can still be on the stack. A job that a service posts to the window
  before it opens runs after it opens.

  On Android, a start-up alert before a user-error halt opens the window during
  the sweep. Its items read no services during the sweep. On the desktop, such
  an alert opens a window of its own and never the emulator window. The alert
  can come while the device configuration loads. The emulator window reads that
  configuration, so it cannot open during the load.
- **The Android frontend boots the emulator on a boot thread.** Qt binds a
  `QObject` service to the thread that creates it. As a result, the GUI thread
  creates the services. A boot thread runs the resolution sweep and the
  readiness sweep, and starts the guest.
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
  A thread that a `JitRunner` pre-start hook starts runs after the readiness
  sweep, so it finds every service ready.
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

## Machine objects

libCerfCore describes the devices of the machine as machine objects. A frontend
discovers them in `MachineObjectTree`.

**A machine object describes what the device is and what a person can do with
it.** It has no primary click, no grayed state, no order on a bar and no group.

**An object id is a fixed name, never the display name of the object.** The
saved state of the object uses the ids of the object and of its parents as its
key.

**A machine object enters `MachineObjectTree` at setup, never on a guest
event.** A restore refuses a saved state whose objects differ from the live
tree.

**A command that needs input from a person asks for it through
`MachineRequests`.**

**A device failure is a failure event with a reason id, never a message box or a
notification.**

**A machine object publishes `kChanged` when its state changes.** The code that
changes the state publishes the event.

**The owner of a device is its machine object.** A wrapper class that only
forwards to the owner is a middle man.

**A card that drives a display gives a frame source to `ExternalDisplays` and
opens no window.**

- `libCerfCore/include/cerfcore/host/machine_object*.h`, `machine_socket.h`,
  `machine_requests.h`, `external_displays.h`, `libCerfCore/src/host/machine_object_tree.cpp`

## PCMCIA

16-bit PC Card emulation, split framework/controller/card:

- **`PcmciaCard`** (`libCerfCore/src/peripherals/pcmcia/pcmcia_card.h`) - the abstract
  card. Cards are plain objects (NOT Services).
  `PcmciaCardCatalog::Create()` creates a card, and its slot owns it. One
  type can occupy two slots at once.

  **A card releases its pins in `PowerOff` / `OnShutdown`, NEVER in a
  destructor.** Nothing ejects a card at shutdown. The card dies inside the
  destructor of its controller, when the members of that controller are
  already gone. A line dropped from a card dtor therefore reaches into freed
  state. And **no Vcc means a card drives no pin, its interrupt included** (the
  socket floats its data lines on the same rule). A card with its own
  host or network thread gates its interrupt on power. If it does not, it
  strands a line on a socket that it already left.
- **`PcmciaSlot`** (`pcmcia_slot.{h,cpp}`) - one physical socket. It owns
  card lifetime and bus serialization. It IS the `MachineSocket` of the
  socket.

  **Card-detect and Vcc (`HasCard` / `IsPowered`) are lock-free reads of
  an atomic pin word, published under the bus lock - keep them that way.**
  A controller reads them from inside its own lock. At the same time, eject
  runs bus lock -> card -> IRQ callback -> that same controller lock. A pin
  accessor that took the bus lock closes an AB-BA against the UI thread.
  Every other slot entry point is a bus transaction, and a host calls it
  with its own lock released.

  **A card that a host inserts after an eject goes in only after 1500 ms of
  guest time.** A guest that compares card-detect states misses a card change
  when it never reads the empty socket. The empty socket must therefore last
  in guest time, also through a pause. `PcmciaSwapGap` holds the card until
  then.
- **`PcmciaCardCatalog`** (`pcmcia_card_catalog.{h,cpp}`) - the
  registry of insertable card types. A new card type is one `PcmciaCard`
  subclass plus one catalog entry.
- **`PcmciaSpaceRouter`** (`pcmcia_space_router.{h,cpp}`) - the shared
  SA-1110/PXA255 static-window PC Card space decode (PA 0x20000000,
  socket/region bits). Controllers call `ProvideSockets`. Never
  re-implement this decode per SoC.

To wire a new board, write a socket controller in the proper tree
(chip/board/vendor-part). That controller owns `PcmciaSlot` instances,
implements `PcmciaSlotHost` (card-detect / IRQ callbacks), adds the slots to
`MachineObjectTree`, and drives `SetPowered` from its power register.

- `libCerfCore/src/peripherals/pcmcia/`

## Serial

Any UART can use the serial stack. The same endpoints serve an
on-SoC UART and a serial PC card. The stack splits into line and personality:

- **`SerialLine`** (`libCerfCore/src/peripherals/serial/serial_line.h`) - the abstract
  UART surface that an endpoint drives.
- **`SerialEndpoint`** (`serial_endpoint.h`) - the "personality" behind a
  line.
- **`SerialCradle`** (`serial_cradle.{h,cpp}`) - the `MachineSocket` of an
  on-SoC UART, the same socket type as `PcmciaSlot` with other insertable
  types.

  **A failed host port ejects its attachment through `DeferredJobs`.** The
  failure of `HostSerialForward` can arrive under the lock of the cradle or of
  the slot bus, so a direct eject deadlocks. `DeferredJobs::Post` runs the
  eject on a host thread, also during a pause. Such a job
  changes guest state only inside `EmulationFreeze::WorkerSection`.
- **`SerialEndpointPort`** (`libCerfCore/src/peripherals/serial/serial_endpoint_port.{h,cpp}`) -
  the one owner of the endpoint side of a serial line.
- `libCerfCore/src/peripherals/serial_pccard/` holds ONLY the PC-card consumer. The
  framework named here is board-neutral and lives in
  `libCerfCore/src/peripherals/serial/`.

To wire the stock UART of a board, implement `SerialLine` on the UART
peripheral. The implementation needs the RX path, an RX interrupt, the baud
from the divisor, and the modem status on the pins that the board wires.
Attach the endpoint and the cradle
through `SerialEndpointPort`. Supply a
per-board seam that names the modem pins. Take those pin numbers from the
serial driver of the board. Never guess them.

- `libCerfCore/src/peripherals/serial/`

## PS/2 mouse

`Ps2Mouse` is the PS/2 pointing device that every board with a PS/2 port
shares.

**A PS/2 packet carries at most ±127 on each axis.** The PS/2 format allows
±255, with the ninth bit in byte 0. The CE mouse drivers read each delta byte
as a signed 8-bit value. They ignore the sign and overflow bits of byte 0. As a
result, a larger value moves the guest cursor the wrong way. In stream mode,
CERF sends a report with more motion than one packet carries as several packets
in the same sample. Because of this, stream mode loses no host motion.

- `libCerfCore/src/peripherals/ps2_mouse/`

## Audio

A consumer receives each guest audio stream through an `AudioOutputs` service. It
feeds each guest microphone through an `AudioInputs` service.

**An `AudioOutputDevice` reports each submitted block as consumed exactly once,
also when it closes or drops its blocks.** The bytes of a block stay valid until
that report. `Submit` returns false on a device that lost its stream. The device
does not keep that block. The core then closes the device.

**An `AudioInputDevice` calls `Captured` only between `Open` and the return of
`Close`.**

The core never calls two methods of one device at the same time. The core never
calls `Open` on the guest CPU thread, so `Open` can block.

- `libCerfCore/include/cerfcore/host/audio_outputs.h`, `audio_inputs.h`,
  `libCerfCore/src/host/wave_out_sink.cpp`, `wave_in_fifo.cpp`,
  `cerf-qt/desktop/host_audio_outputs_*`, `host_audio_inputs_*`,
  `cerf-qt/android/android_audio_outputs.cpp`, `android_audio_inputs.cpp`

## CPU reset & cold boot

**`GuestCpuReset`** is the funnel for every CERF-initiated CPU reset
(host reset actions, watchdog expiry). Never call bare
`ArmJit::SetResetPending`. The SoC peripheral that owns the reset-cause
register implements `ResetCauseLatch` (warm / cold / watchdog), so the
re-entered guest boot path reads a true reset cause. Its `ReportOnlyWarmReset`
sets the register to the cause of a warm reset, with no other cause. Other
parts can also report a reset cause to the guest, for example a second status
register or a board microcontroller. Such a part reports the same cause as the
latch. It reports a warm reset when `DeliveredResetReportedWarm()` is true,
also during a reset of the power-on kind. Some guest
writes reset the SoC with a cause that the latch does not name, for example a
software reset bit. The peripheral that takes such a write latches that cause
itself, then calls `ResetWithLatchedCause`. Peripherals whose
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

**An interrupt edge that a release listener causes still falls inside the
reset.** No guest instruction runs between the first reset listener and the
last release listener, and `GuestCpuReset::Delivering()` is true for that whole
span. Some interrupt controllers hold their status clear for the duration of
reset. Such a controller latches no edge in that span if the reset is of a kind
that resets it.

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

**A reset delivery replays the writes only on a hard reset and on a warm
boot.** A bootloader can copy the OS image into RAM also on a reset that keeps
RAM. The stand-in of such a bootloader replays the writes where that
bootloader copies the image. Without the replay, that reset enters RAM that
the guest used for other data.

A warm boot from a saved image fills RAM, and flash for an image of the
same ROM, from the image in place of the wipe.

- `libCerfCore/include/cerfcore/boot/guest_cold_boot.h`, `libCerfCore/src/boot/guest_cold_boot.cpp`

## Host window & presentation

This section covers the emulator window of a frontend, its drawable area, and
the render and input plumbing that connects the host UI to the guest.

- **`FrontendWindow`** - the emulator window seam of cerf-qt.

  The emulator window is a service of its own type. Frontend code resolves the
  window by that type. A private subclass of `FrontendWindowAdapter` fills
  the `FrontendWindow` slot. That subclass forwards each call to the window
  service.

  `EmulatorWindowHost` holds what the host decides about the emulator window.

  The chrome of a window is the frame and the bars around its content. **A fit
  takes the chrome from the frame margins and from the bar height that the window
  reports.** The sizes of the window and of its items cannot give the chrome.
  After a resize request, `QWindow::geometry()` can have the new size at once.
  The items get the new size only when the resize event arrives. On Wayland, the
  items have no size until the first configure event.

  **A window event that CERF caused never counts as a user resize.** Qt Quick
  marks every window state change as spontaneous, that is, as an event from the
  window system. As a result, the event alone cannot show its cause. A platform
  can deliver the event inside the call that requests
  the change, or after the next request. The desktop host records each window
  size and window state that it requests before it calls Qt. An event inside
  that call, or an event that matches a recorded request, is CERF's. A change of
  the bars inside such a call starts no refit, for example when full screen ends.

  On macOS, a window sends the size of its new platform window as a resize event
  when it shows for the first time. A resize event before CERF places the window
  never counts as a user resize.
  - `cerf-qt/frontend_window.h`, `cerf-qt/frontend_window_adapter.{h,cpp}`,
    `cerf-qt/qt_frontend_window.cpp`, `cerf-qt/qt_emulator_window.{h,cpp}`,
    `cerf-qt/emulator_window_host.h`, `cerf-qt/desktop/desktop_emulator_window_host.cpp`,
    `cerf-qt/android/android_emulator_window_host.cpp`

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
  - `cerf-qt/android/android_system_bars.{h,cpp}`,
    `cerf-qt/android/package/src/cx/cerf/SystemBarsWatch.java`

- **The canvas** - the drawable area of the emulator window. It implements
  `CanvasInputHost` and owns the one transform from host pixels to
  guest-surface coordinates (`HostToGuest`). As a result, taps land on the
  rendered image.

  On Android, the canvas turns touch into pen and pointer gestures. On the
  desktop, touch reaches the canvas as mouse input.

  **A locked relative mouse takes relative motion from the host where the host
  offers it.** On Windows the canvas reads raw mouse input and keeps the cursor on one
  point of the canvas. On macOS it detaches the cursor from the mouse and reads
  the deltas of the mouse events. On Wayland it uses the relative pointer and the
  pointer lock of the compositor.

  On X11 the canvas warps the pointer back to its center and computes each delta
  from two event positions. A mouse capture of the canvas grabs the pointer of
  the window system, so the canvas also gets the moves outside the window. Every
  warp drops the stored position of the last event, also when the pointer
  already rests at the center. Windows and macOS deliver no move outside the
  window. On these hosts, a fast move can leave the window between two events and
  escape this lock.
  - `cerf-qt/guest_surface.{h,cpp}`, `cerf-qt/qt_pointer_lock*`

- **The frame stage** - a Qt Quick scene graph draws the canvas. The GPU scales
  and turns the guest frame. A frame never uploads the guest frame at the size of
  the window.

  **A new texture can get the sampler of a texture that CERF freed.** Qt keeps one
  sampler table for each material shader. Qt rebuilds the table only when the
  bound texture has another address than the texture before it, or when the filter
  of the texture changed. A new texture can get the address of a freed texture.
  The new texture then uses the filter of the freed texture, for example a linear
  filter on a frame that must use the nearest filter.

  Every scene-graph texture that CERF creates therefore passes through
  `FreshSampler`. That function changes the filter of the new texture once, so Qt
  rebuilds the sampler when it first binds the texture.
  - `cerf-qt/qt_frame_presenter.{h,cpp}`, `cerf-qt/frame_scene_node.{h,cpp}`,
    `cerf-qt/frame_view_item.{h,cpp}`

- **Shaders** - librashader runs the shader chain of the device on the guest
  frame. A shader chain is a list of slang presets in order. The presets load as
  one librashader preset, through the CERF patch `libra_preset_create_chain`. The
  presets live in the `shaders` folder of the installation. The bundled presets
  come from `bundled/shaders/`, and an import goes into the same folder.

  **A chain refuses two presets that use the same name.** librashader keeps one
  table of names for the whole chain: pass aliases, `#pragma name` values, texture
  names and the names that it makes from them. A second entry with the same name
  replaces the first, so a pass of one preset reads a texture of another preset.
  A parameter name that two presets share is one value for both. Two presets can
  load the same image file as a texture under the same name. When the wrap mode,
  the filter mode and the mipmap flag also match, the chain loads that texture
  once for both presets.

  librashader has one runtime for each graphics API. CERF uses the runtime of the
  graphics API that the window uses. Each runtime is a library of its own. The
  Direct3D 11 library needs Windows 8, so Windows 7 uses only the OpenGL library.

  **The input texture of a runtime holds the guest frame in a format that
  librashader can copy into a history texture without a change.** A history
  texture keeps an earlier frame for the passes that read it. The OpenGL runtime
  copies with a framebuffer copy, and a texture swizzle remaps the channels of a
  texture fetch only. The Direct3D 11 runtime has no BGRA format, and its copy of
  a BGRA input fails. The OpenGL and Direct3D 11 inputs therefore hold RGBA.

  **The chain never receives a frame that CERF dims.** CERF dims the guest frame
  while the emulator is paused or the guest is asleep. A chain keeps history and
  feedback frames from one frame to the next, so a dimmed input stays in its
  state. While CERF dims the frame, the chain renders the clean frame once and
  stops. The screen shows that output dimmed, and Save and Copy take it without
  the dimming.

  **A preset change builds a new chain. A parameter change only sets the values on
  the live chain.** A build compiles every shader pass of the chain. A rebuild at
  each step of a slider therefore stalls the frame.

  **Every render of the chain runs before the main pass, inside
  `beginExternalCommands` and `endExternalCommands`.** The live chain renders in
  `QSGRenderNode::prepare`. The frozen frame of a paused device renders while the
  scene graph syncs. CERF drops a chain that fails to build or render, and the
  frame shows without shaders.
  - `cerf-qt/shader_selection.{h,cpp}`, `cerf-qt/shader_runtime*`,
    `cerf-qt/shader_chain_node.{h,cpp}`, `cerf-qt/shader_library.{h,cpp}`,
    `tools/librashader_library.py`, `tools/librashader_patch/`

- **`FrameRenderer`** (abstract) - one producer of guest frames. The extent
  that `PresentedSize` gives is already in presented orientation, so a renderer
  that rotates the image reports the swapped extent.

  **`PresentedSize` is the only authority on the panel-enable edge.** The
  frontend posts the edge to the UI thread, and the UI thread reads the size
  through `PresentedSize`. A peripheral must never pass its own dimensions to
  the host. A renderer can draw at a different extent than the panel timing. If
  a peripheral passes its own dimensions, the window size disagrees with the
  image.

  The size read stays on the UI thread by construction. A publisher usually
  reaches `PanelEnabled()` with its own peripheral lock held, and
  `PresentedSize` goes back into that same peripheral. A read on the
  publishing thread therefore re-locks a non-recursive mutex. The JIT thread
  and the UI thread then block each other.

  `PresentedSize` is not the only source of the guest-surface size.
  `FrontendWindow::SetGuestSurfaceSize` is the single entry point. A restore
  installs the size from the state image, which `PresentedSize` never produced.

  These slots build on this base:

  - **`PanelFrameRenderer`** - the physical panel scanout of the board. Every
    hardware renderer registers here. Its `ShouldRegister` gates on hardware
    presence only (board, SoC or part). It never gates on guest additions.
  - **`GuestAdditionsFrameRenderer`** - the guest-additions virtual
    framebuffer under `libCerfCore/src/peripherals/cerf_virt/`.
  - **`FrameRenderer`** itself - the presented surface,
    **`PresentedFrameRenderer`**. A frontend binds this slot, never a layer
    slot.

  **libCerfCore composes the presented frame. A frontend only draws the frame
  that `FrameRenderer` gives it.**

  **The angle of the frame is an attribute of the emulated device,
  `FrameRenderer::DisplayQuarter`.** A frontend adds the turns of the user to
  it, and it never turns the frame for the guest itself.

  **`PresentedFrameRenderer`** is an ordered stack of the two layers above.
  The panel layer renders under the guest-additions layer. A splash that the
  bootloader or the kernel draws therefore stays visible until the
  guest-additions driver writes to the frame that it displays.

  The layers are opaque, and the compositor skips each covered layer. The
  compositor must not blend the layers per pixel. The guest-additions surface
  has areas that are legitimately black, and a blend makes the panel layer
  visible through them.

  **`HasFrame` reports the state of the display hardware, never the content of
  the frame.** A frame that is black or unchanged is still the frame that the
  hardware shows. A frontend that has its own boot screen decides by itself
  when it leaves that screen.

  To add a layer, register it on its own role slot. Then put the layer in the
  order of the compositor.
  - `libCerfCore/include/cerfcore/host/frame_renderer.h`, `panel_frame_renderer.h`,
    `guest_additions_frame_renderer.h`, `libCerfCore/src/host/presented_frame_renderer.cpp`

- **`HwScreen`** - the hardware text console behind the `Tab::Hw` tab. It
  holds the RX/TX text of the guest UART /
  OEM-debug output and the notices of CERF itself (power events, save/restore
  progress).
  - `libCerfCore/include/cerfcore/host/hw_screen.h`, `libCerfCore/src/host/hw_screen.cpp`,
    `cerf-qt/hw_screen_log.{h,cpp}`, `cerf-qt/qml/HardwareConsole.qml`

- **`NotificationStack`** is the card stack over every canvas tab, and it takes
  only notices that interrupt the user's workflow, never routine events.

- **`OverlayInput`** - the one owner of the input for the overlays above the
  guest canvas, for example the notification cards and the HUD. A press goes to
  the top overlay at its point. That overlay owns the pressed button of that
  pointer until the release of the button. A left press on a HUD control also
  owns the motion of the pointer until its release.

  Every other button and all other motion stay with the route that owns them.
  The guest never sees a button that an overlay owns. When the window loses the
  pointer, for example when it loses activation, every overlay press ends. A
  guest route that releases the host capture does not end an overlay press.

  On Android, one Qt Quick item above the canvas takes each touch and mouse
  press on an overlay, in every pointer mode. Each source of pointer events is
  a producer of this service, and a pointer id has a meaning only inside its
  producer. A new overlay is a layer of this service, never a check in another
  overlay or in a guest input route.
  - `cerf-qt/overlay_input.{h,cpp}`, `cerf-qt/overlay_touch_area.{h,cpp}`

- **`BootScreen`** - the CERF-logo boot animation behind the `Tab::Boot` tab.
  - `cerf-qt/boot_screen.{h,cpp}`, `cerf-qt/canvas_tab_view.{h,cpp}`, `cerf-qt/qml/BootScreenLayer.qml`

- **`TouchInput`** (abstract) - takes host pen events in guest-surface
  coordinates.
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

  **After a HUD toggle or a view turn, the desktop window takes the size of the
  new box when it can.** This also occurs after a user resize. Some guests cannot
  change their resolution. The guest resolution changes only when the window
  cannot change. That occurs when the window is maximized or full screen, or when
  the box does not fit the screen. Then a Guest Additions live resize fits the
  guest to the canvas, if the guest supports it.

  **On the desktop, the HUD is the hardware layout of the device.** It sits around
  the framebuffer as the preset sets it, and it turns with the framebuffer.

  **On Android, the HUD is a control surface of the screen.** It sits at the sides
  of the safe zone and is always upright. A framebuffer rotation never turns it. The
  rotation can only change where a panel goes, because it changes which space the
  framebuffer needs.

  **On Android, the content of a panel decides how it can move.** A panel whose
  content is a column of two or more rows is a key matrix, for example a keyboard or
  a phone keypad. It keeps its layout. It moves to the other axis only when it has at
  least as many rows as cells in its longest row. Every other panel turns its rows
  into columns when it moves to the other axis. A panel that turns onto the top or
  bottom gets deep enough for each rocker to be as tall as it is wide.

  The main panel is the first panel with a full d-pad.

  While the safe zone is taller than wide, a top or bottom panel stays where it is.
  A side panel that can move goes to the bottom when it holds a d-pad or a rocker,
  and to the top when it does not. The main panel goes to the bottom when it can move
  there.

  While the safe zone is wider than tall, or square, a side panel stays on its side.
  A top panel can move to the left and a bottom panel to the right. CERF keeps the
  moves that give the framebuffer the largest fit. Of two sets of moves with an equal
  fit, it keeps the set with fewer moves.

  On each side, the panels stack outward in list order, and the main panel is at the
  edge of the screen. CERF centers every panel on its side.

  **On Android, the HUD uses the real size of the guest surface.** A Guest Additions
  resolution changes the space that the framebuffer needs, so the panels follow it.
  When Guest Additions take the resolution from the screen, the surface follows the
  HUD instead. The HUD then takes the bound screen that is closest to the configured
  screen size, not to the size of the framebuffer. When the window opens, the guest
  takes the size of the area in which the view mode shows the guest. As a result, the
  guest shows at 1:1. A later rotation or a later change of the view mode keeps that
  guest size.

  **On Android, the whole HUD has one scale.** The HUD grows until its smallest
  control has the size of a fingertip, or until a panel fills its side. It never
  takes space that the framebuffer needs at the scale at which the HUD and the
  framebuffer together fit the safe zone. As a result, a small key panel beside a
  large screen grows into the space that the framebuffer cannot use. On a large
  screen, the HUD stays at the size of a fingertip, and the framebuffer gets the rest.

  The framebuffer fits, pans and zooms in the rest of the canvas. A touch inside the
  HUD band never reaches the guest.
  - `cerf-qt/hud_selection.h`, `cerf-qt/hud_controls.h`, `cerf-qt/hud_nodes.h`, `cerf-qt/qml/HudLayer.qml`,
    `cerf-qt/view_presentation.h`, `libCerfCore/include/cerfcore/host/device_buttons.h`

- **`ViewRotation`** - the quarter turns of the user, on top of the angle of the
  frame. The host-to-guest point map and the relative mouse deltas turn with the
  frame. The rotation lasts for the session only.
  - `cerf-qt/view_rotation.h`

- **`KeyboardInput`** (abstract) - one keyboard source.
  - `libCerfCore/include/cerfcore/host/keyboard_input.h`

- **`KeyboardRouter`** - the keyboard-source registry and host-key funnel.

  **A key belongs to the source that receives its key-down.** That source
  receives the key-up of the key, also after the active source changes. A
  key-down of a key that another source holds releases the key on that source
  first. A key-up of a key that no source holds reaches no source.

  **The router selects the highest-priority source that reports
  `SourceReady`.** When no source is ready, the router selects the highest
  priority overall. A board with no stock keyboard must not have dead input.

  A guest reset re-runs that selection, so the stock keyboard is active again
  until a source reports `SourceReady`.

  A manual choice of the active source suppresses automatic selection until the
  next reset. The router keeps that choice across hibernation.
  - `libCerfCore/include/cerfcore/host/keyboard_router.h`, `libCerfCore/src/host/keyboard_router.cpp`

- **`PointerRouter`** - the pointer-source registry and host-mouse funnel. A
  frontend sends each host mouse event to `Route` in guest-surface coordinates,
  and the router sends it to the active source.

  **A pen or a mouse button that is down stays with the source that received
  the press.** This holds also after the active source changes. A host mouse
  event that reports the button up releases it on that source.

  **Every relative motion and relative button goes through `OnRelativeMove`.**
  The router keeps the relative buttons of the last call. A frontend releases
  them only from a relative-mouse lock that is engaged. A release outside that
  lock drops the buttons of another relative producer, for example the Android
  gesture pointer.
  - `libCerfCore/include/cerfcore/host/pointer_router.h`, `libCerfCore/src/host/pointer_router.cpp`,
    `cerf-qt/canvas_input.{h,cpp}`

- **`InputCapture`** - the capture toggle, so the guest receives the keys
  that the host shell normally takes. On Windows, the desktop frontend takes
  them from `LowLevelKeyboardHook` and installs that hook on the UI thread.
  - `cerf-qt/input_capture.{h,cpp}`, `cerf-qt/desktop/qt_input_capture_windows.cpp`

- **Menus and dialogs** - on the desktop, every menu and every dialog is a
  top-level window. The CerfStyle style draws them, except the file dialogs and
  the macOS menu bar, which are native to the host. CERF never shows a Win32
  menu, and never shows a desktop menu or dialog inside the emulator window.
  Many guests are QCIF or QVGA sized, so a popup inside the window does not
  fit. On Android, menus and dialogs stay inside the window. The menu bar that
  CerfStyle draws has the look of the status bar.

  **A dialog window has the size of its content.** Qt gives the window of a
  popup no size limits. Without its own limits, the user can resize or maximize
  a dialog window.

  **On the desktop, a window that opens over the emulator window does not block
  the device.** The user can use the device while the window is open. A window
  that opens over such a window does not block either. A prompt or an alert that
  waits for an answer stays modal, for example the shutdown prompt.

  **Only one window of each kind is open.** A second request for an open window
  brings that window to the front, and shows the page that the request names.

  **A menu of the drawn menu bar gets its items while it is closed.** Qt shows
  the popup window before it emits `aboutToShow`, so a menu that builds its
  items there changes while it is already on screen.

  **On macOS, CERF builds the menus of the menu bar in AppKit.** A menu row is
  one menu item with a view that holds the buttons of the row. A native menu
  item of Qt Quick cannot hold a view. Qt replaces the main menu while a Qt menu
  bar exists, so no window on macOS has a Qt menu bar. When a window with menus
  becomes active, its menus replace the menus of the other window. The About
  and Settings items go to the application menu, where macOS has them.

  **An item of the application menu gets its action after it enters the
  menu.** Qt keeps a hidden Preferences item with the Command-comma key in the
  application menu. A CERF item with the same key loses that key when it enters
  the menu with its action already set. Command-comma then opens nothing.

  **A menu popup window is translucent.** Qt clears it with a transparent
  color. On Windows, the filter that paints a window background on
  `WM_ERASEBKGND` paints opaque windows only. A fill under a translucent window
  shows as black corners and a black fade.

  **On Wayland, a menu has no exit transition.** The menu bar opens the next
  menu before the old menu closes. Wayland closes a new popup together with the
  old popup that still holds the grab. As a result, a fading old menu closes the
  next menu.

  **The press that closes a menu never reaches the guest.** On the desktop, Qt
  forwards a press outside a popup window to the window under it.
  `MenuDismissFilter` swallows that press. Qt can deliver the release of the
  press to the popup that closes, in place of the window. As a result, the
  filter stops at the first later event that shows the button up, not only at a
  release. On Android, a menu over the guest is a modal popup with no dim, so Qt
  keeps the press that closes it.

  **A press inside an open menu never reaches the guest.** On the desktop, Qt
  gives each press to the menu window first. The window under the menu gets the
  press only when no menu window accepts it. No menu window accepts a press on a
  parent menu while its submenu is open. `MenuDismissFilter` swallows a press
  that reaches the emulator window when the press lies inside a visible popup
  window.

  **Qt 6.8.4 reports a press that a menu item accepts as not accepted.** The
  window under the menu then gets the press too. For that reason, the Windows
  build of Qt carries the upstream fix for QTBUG-139342.

  **The release of the press that opens a menu clicks nothing.** A menu can
  open under a still pointer, for example a bar menu that slides over its bar
  item near the edge of the screen. On a release, Qt clicks the item that hover
  highlighted. When a menu opens, it takes the pointer position from the item
  or the point that opens it. Its items take hover only after the pointer moves
  more than the drag distance of the platform from that position. A new press
  on an item still clicks it.

  **A menu takes no pointer position until it is open.** On Wayland the menu
  window can move while it opens. Qt then reports the still pointer at the same
  point of the moved window, which is a new global position. When no item or
  point opens the menu, the first pointer position after the menu opens is the
  position that the drag distance counts from.

  **A press on the item that opens a menu, a drag and a release click the menu
  item under the release.** The item that takes the press keeps the press
  grab, so it gets every move until the release. Qt can then deliver the drag
  moves to that item and no hover to the menu window. On the desktop, the menu
  window therefore drops a press grab that an item of another window holds.

  On every host, a URL that a file dialog returns becomes a path only through
  `FileAccess::LocalPath`.
  - `cerf-qt/qml/HostMenuBar.qml`, `cerf-qt/qml/EmulatorMenu.qml`,
    `cerf-qt/menu_dismiss_filter.{h,cpp}`, `cerf-qt/CerfStyle/{Menu,MenuItem}.qml`,
    `cerf-qt/CerfStyle/menu_drag.{h,cpp}`,
    `cerf-qt/CerfStyle/Dialog.qml`, `cerf-qt/cerfman/file_access.{h,cpp}`,
    `cerf-qt/desktop/qt_window_erase_windows.cpp`, `cerf-qt/desktop/global_menu_bar{.h,_macos.mm}`,
    `cerf-qt/menu_source.h`

- **`FillColorItem`** - the base of the frame view.

  **The guest frame sits on whole device pixels.** At a fractional scale, an item
  can start between two device pixels. For example, 26 logical pixels at a scale
  of 1.25 are 32.5 device pixels. Nearest sampling then reads each texel (a pixel
  of the texture) at its edge, and rows or columns shift from frame to frame.
  `FillColorItem` moves the content to the nearest whole device pixel.

  **The device pixel ratio is not the scale at which Qt draws.** Qt divides the
  pixel size of the render target by the device pixel ratio and rounds the result
  to whole logical pixels. Then it maps that logical size onto the full pixel size.
  For example, 813 device pixels at 1.25 become 650 logical pixels, so one logical
  pixel spans 1.25077 device pixels. Content then moves off whole device pixels, by
  up to half the ratio at the far edge of the window.

  `WindowPixelScale` measures the viewport after each render pass and gives the
  real scale on each axis. Every conversion between logical pixels and canvas
  pixels uses that scale, never the device pixel ratio.
  - `cerf-qt/fill_color_item.{h,cpp}`

- **Bar widgets** - cerf-qt presents each machine object that it shows as a
  bar widget. A bar widget is an icon, a tooltip and a menu on the status bar
  or the Android strip. A feature of the frontend itself, such as the
  capture/lock indicator, can be a bar widget too.
  - `cerf-qt/bar_widget*.{h,cpp}`, `cerf-qt/*_bar_widget*.cpp`, `cerf-qt/socket_menu.{h,cpp}`,
    `cerf-qt/qml/WidgetBar.qml`, `cerf-qt/qml/BarWidgetIcon.qml`

- **`Screenshots`** - screenshot + clipboard capture of the live guest
  surface (via `FrontendWindow::CaptureGuestSurface`, 1:1). The desktop
  saves a screenshot in the `screenshots` folder of CERF. Android saves
  it in the gallery, in Pictures/CERF.

  If the device has a shader chain, Save and Copy take the output of the chain at
  the size that the screen shows. The `screenshots` key of the `shaders`
  configuration turns this off. If the chain does not shade a frame, Save and Copy
  take the 1:1 capture. The live thumbnail and the saved-state preview always take
  the 1:1 capture.

  **A shaded capture waits for the next frame that the window renders.** A window
  that the window system does not expose (does not show on a screen) renders no
  frame. A minimized window is one example. Save and Copy then take the 1:1
  capture at once.
  - `cerf-qt/screenshots.{h,cpp}`, `cerf-qt/screenshot_store.h`,
    `cerf-qt/desktop/screenshot_folder_store.cpp`, `cerf-qt/android/android_gallery_store.cpp`

- **The color scheme can switch while CERF runs.** Every window follows a switch
  in both directions. Each window also follows a switch back to a scheme that the
  platform reports as unknown, for example the GNOME `default` setting. Test a
  theme change with a switch while the window is open. A fresh start does not
  show a defect of the switch.

  The Material accent of the Qt Quick windows comes from `SystemAccent`, which
  reads the accent of the host system. A host gives the accent color only.
  `SystemAccent` calculates black or white text from the brightness of the
  accent. This calculation is the same on every host.
  - `cerf-qt/CerfStyle/system_accent.{h,cpp}`, `cerf-qt/CerfStyle/host_accent*`

## Automatic touch calibration

`AutoCalibration` finds the touch calibration screen of the guest and presses its
targets with the stock touch input. It is a procedure in libCerfCore. A frontend
implements its `CalibrationHost` seam.

**Calibration reads the presented frame from `FrameRenderer` itself.** A frontend
never carries a frame of the core back to the core.

Do not loosen the target match to find more calibration screens. A wrong press
touches a real guest window.

The presses go through the stock `TouchInput`, also when guest additions run.
Calibration reads raw touch samples below GWES. The guest-additions pointer
enters above GWES, so it cannot reach the calibration.

The press cursor of a frontend is an overlay on the canvas, never a part of the
guest surface that the scan reads. A `CalibrationHost` call that blocks returns
its closed answer when the frontend shuts down.

While CERF presses the targets, it holds `HostPointerInputLock`. Every core
entry that takes host pointer input drops that input while CERF holds the lock.

- `libCerfCore/include/cerfcore/host/auto_calibration.h`,
  `libCerfCore/include/cerfcore/host/calibration_*.h`,
  `libCerfCore/include/cerfcore/host/host_pointer_input_lock.h`,
  `libCerfCore/src/host/auto_calibration.cpp`, `libCerfCore/src/host/calibration_*`,
  `libCerfCore/src/peripherals/cerf_virt/cerf_virt_calib_signal.cpp`,
  `cerf-qt/qt_calibration_host.cpp`, `cerf-qt/guest_calibration_fallback.{h,cpp}`,
  `cerf-qt/surface_cursor.{h,cpp}`

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

## Callback lists

`CallbackList` in the `cerfengine/callback_list.h` header of libCerfEngine holds
the callbacks of a unit. It calls all of them in the order in which it received
them. Each callback gets the same arguments. The list uses no result of a
callback. libCerfCore code includes it as `cerfcore/core/callback_list.h`. A unit
that calls a list of callbacks only in this way keeps the list in a
`CallbackList`.

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

On x86-64 Linux the build runs the same toolchain through Wine. macOS and ARM64 Linux cannot
run it, so a build there copies the CE apps of a Windows or x86-64 Linux build
(`build.py --ce-apps-from`).

The Android package (`build.py --android`) carries every CE app inside the APK. As a result,
the CE apps must exist before the frontend builds. A partial set of CE apps must not ship.
