## File & Symbol Style

- **Headers declare, .cpp files implement.** Declaration and implementation live together: `foo.h` + `foo.cpp` in the same directory. Never forward-declare in one module's header and define in an unrelated module's .cpp. In a core library, each public header lives in `include/<library>/`, and the `.cpp` of that header lives in `src/` at the same relative path. A host-platform layer is the code that calls the host operating system. It has one header and one `.cpp` for each host platform, named `<header>_<platform>.cpp`. The hosts that share one body take `<header>_default.cpp`. Every host compiles that file unless it has its own `.cpp` for that header. A core library can declare a host function that its consumer defines. The consumer defines it in the `.cpp` of the service that owns the body.
- **500-line cap per source file (any language), enforced by the pre-commit hook. A file past the cap is NEVER permission to violate any other rule on this page.** The cap is a forcing function, not an escape hatch. If compliance with the cap appears to require a breach of another rule (most commonly "One service = one `.h` + one `.cpp` pair" in § Services, or "No misc/grab-bag files" below), the design is wrong, not the rules. When a file approaches the limit, the only sanctioned response is to split by responsibility - never by alphabet, method-prefix, "part 1 / part 2", or `_helpers` / `_extras` / `_impl` / `_internal` sidecars. Never fit a file under the cap by joining lines, packing several declarations onto one line, or deleting blank lines. A file that fits only through such compression is over the cap, and the split is due before the file goes to review. **For services specifically, "split by responsibility" means a split of the service itself into multiple smaller services**, each with its own state, its own one-sentence responsibility, and its own `foo_service.{h,cpp}` pair that follows every rule in § Services. A single service spread across two `.cpp` files is forbidden, regardless of how close to the cap the original file is. The same holds for a spread across a header and a sibling `.cpp` that belongs to a different module. If you cannot describe the new responsibility boundary in one sentence per resulting service, you have not found the split.
- **No misc/grab-bag files.** Never create `misc.cpp`, `helpers.cpp`, `extras.cpp`, `util2.cpp`. Every file's name describes a single responsibility.
- **Naming** - classes `PascalCase`, methods `PascalCase`, members `snake_case_`, free helpers `PascalCase`. Filenames `snake_case.{h,cpp}`.
- **Includes** - include a header from the `include/<library>/` tree of a library by its library path, for example `<cerfcore/core/log.h>`. Inside that tree, include another header of the same tree with a relative path. Include every other project header with a relative path (`"../core/log.h"`). Include system headers with angle brackets. When windowsx/GDI identifiers collide, put `#define NOMINMAX` before `<windows.h>`.
- **Do not reach past CERF's abstractions to call host APIs that CERF owns the answer to at runtime.** When the running guest can observe CERF's internal answer to a question (emulated peripheral state, virtual-platform behavior the guest depends on), host-side code must consult CERF's surface and must not ask the host directly - a bypass produces values the guest was not supposed to see. (This rule is about runtime guest-observable answers. It does not block bootstrap-time host file reads against the bundled tree.)

## Text encoding

CERF runs on hosts in every locale. The ANSI code page is different on each of
them, and it encodes only a part of Unicode. CERF therefore never uses the ANSI
code page.

- **Every `std::string` and `char*` in host code holds UTF-8.** This includes
  paths, configuration values, command-line arguments and display text.
- **Call the W form of each Win32 API.** Convert a UTF-8 argument with
  `Utf8ToWide` at the call. Convert a wide result back with `WideToUtf8`. Do not
  call an A form. Do not give `CP_ACP` to a conversion.
- **Open a file through a wide path.** MSVC decodes a narrow path in
  `std::fstream`, `std::filesystem::path` and `fopen` with the ANSI code page.
  Give them `Utf8ToWide(path)`, or use `_wfopen_s`.
- **Test each path or text change with characters that the ANSI code page
  cannot encode.** A test with ASCII names proves nothing about encoding.

## Comments

- **A comment is a CITATION, or it does not exist. There is no third kind.** A citation names the external source of truth for the code beneath it: a chip datasheet section, a CPU architecture manual section, a decompiled guest address with its ROM bundle name, a standard or RFC clause, or a permissively-licensed attributed source. That is the entire permitted set, and it is further bounded by `rules.md` § Reference Licence Hygiene - a source in that section's forbidden set is never cited here, whatever the citation would otherwise be worth. Everything else is forbidden - rationale, narration, restatement, design defense, alternatives history, background - as is any sentence that still reads fine with the code deleted. If you cannot name a source, write no comment. This applies in every file type, `.cpp` / `.h` / YAML / MSBuild / PowerShell / batch / CMake alike. Build infrastructure is not exempt.
- **Rationale is more dangerous than a wrong citation, not less.** A wrong citation dies the moment someone opens the reference. A confident wrong rationale is BELIEVED, and it outlives the code it defends. The urge to make the reader understand a hard decision is the tell that you are about to write one.
- **Default: no comment.** Well-named identifiers explain the WHAT. Do not narrate what the next three lines do.
- **Delete a non-citation comment your edit touches.** A reword or a revert keeps the prose.
- **Never reference any document that is not durably committed to the repo. Checklists (anything under `docs/ai_checklists/`) are additionally CONFIDENTIAL - they are private design material, not part of the public repo, and never will be. The `docs/ai_checklists/` path is `.gitignore`d, so `git stash` (with or without `-u`), `git diff`, and `git status` do not see those files. Edits to a checklist survive every git operation transparently, and any procedure that proposes to stash, stage, or diff a checklist change is incoherent - operate on checklists as plain disk files only.** Code that mentions a checklist's filename, section numbers (`§3.1`, `§7.2`, …), phase names, internal taxonomy, or any other design vocabulary lifted from it LEAKS the checklist to every reader of the public source. That is a confidentiality breach, separate from and on top of the rotting-reference problem. Tasks, PRs, tickets, agent-curated planning files, gitignored work-in-progress, scratch design docs, "the MPA design", "see the spec" all rot the same way. Checklists rot AND breach confidentiality, so the prohibition is absolute and total. Forbidden examples (do not write, do not approximate, do not rephrase): `/* added for clipboard fix */`, `/* per checklist §3.1 */`, `/* see docs/ai_checklists/foo.md */`, `/* per the MPA design */`, `/* Step 11 of the spec */`, `/* see Phase 2 */`. A reference to anything inside this project - a sibling source file, `agent_docs/`, `CLAUDE.md` - rots the same way and is not a citation either. A citation names a source OUTSIDE the project, from the permitted set in `rules.md` § Reference Licence Hygiene. Do this test before you add a comment: does a fresh developer at a fresh clone of this repo understand the WHY from this comment alone, with no checklist in hand? If yes, the comment stands. If no, inline the rationale or skip the comment.
- **Reference citations ARE comments, and a citation in the file is OPTIONAL.** Non-trivial peripheral behavior needs its reference (chip datasheet section, architecture reference manual section, standard clause, decompiled guest address with its ROM bundle name, or a permitted open-source model per `rules.md` § Reference Licence Hygiene). That reference must reach the transcript to the user. When a review runs, it must reach the `/verify` prompt too - see `workflow.md` § Reference Citations. A citation in the source file is optional, and a comment of any kind is capped at 3 lines. Uncited code is the normal shape of this codebase: absence of a comment is never a finding, and no reviewer can demand one. A citation attached to code you did not read is fabrication.
- **No "removed X" / "TODO later" comments** for work that is actually done. If the code is gone, the comment is gone.
- **A comment that still makes sense moved to a random file is dead weight** - useful comments are glued to the specific code below them (non-obvious invariants, CE quirks, pointer-truncation hazards). Generic narration ("lives in X", "moved to Y", "added for debugging", "out-of-line in Z") reads the same anywhere, because it says nothing about what is actually there.

## The `CERF_DEV_MODE` gate

`build.py` sets `CERF_DEV_MODE` to `1` for a dev build and to `0` for a
production build. The preprocessor then deletes the gated code from the shipped
binary.

**Gated code must not reach a production build, because it harms the user. A dev
build keeps that code, because a developer needs it, and the harm does not apply
to a developer.**

Name both reasons in the message that carries the change: the harm to the user,
and the need in the dev build. **A gate with no reason is a rule violation.**

## Logging

- **A LOG line is a record of an event, not prose.** It carries the event and the values a reader needs to act on it (register, address, value, PC, function). Narration, rationale, design defence, apology, TODO text, and anything lifted from the session that produced the code are the same bloat that § Comments bans, and they are banned here for the same reason. This binds hardest on the `LOG` immediately before a `CerfFatalExit`, because that one line is what a user pastes back: it states what was hit and with which values, never an essay about why the path is unimplemented.
- **Structured log channels** - `LOG(MEM, ...)`, `LOG(NET, ...)`, and more. One channel per subsystem. New subsystem → new channel in `log.h`, not a generic fallback. The exact set of channels is in flux during the v2 rewrite. Align new code with whatever channels exist when you write it, and add a new one when no existing channel fits.
- **Default log mask is mode-gated.** Dev builds (`CERF_DEV_MODE=1`) enable every channel by default. Production builds (`CERF_DEV_MODE=0`) enable the always-on channels and the event/milestone channels that stay low-volume on every board. The user widens or narrows that set with `--log=...` / `--no-log=...`.
- **Verbose LOG lines that print inputs/state are acceptable permanently - but only when low-frequency** - the log level filters them, and they aid future debugging at zero runtime cost. That holds when their fire-rate is low enough that the signal a future reader needs is not buried in their noise. For a site that fires more often than that, `agent_docs/rules.md` § "Simple LOG verbose lines" gives the frequency test and where the site must go.

## Services

A **service** is a class owned by `CerfEmulator` via `ServiceRegistry`, accessed through `emu.Get<T>()`. All stateful, device-visible host-side behavior lives in a service. Free functions that take services as parameters are technical debt (see `rules.md`).

### Writing a service

```cpp
/* foo_service.h */
#pragma once
#include <cerfcore/core/service.h>

namespace cerfcore {

class FooService : public Service {
public:
    explicit FooService(CerfEmulator& emu) : Service(emu) {}
    void OnReady() override;

    bool DoThing(int arg);
};

}

/* foo_service.cpp */
#include "foo_service.h"

namespace cerfcore {

REGISTER_SERVICE(FooService);

void FooService::OnReady() {
    /* self-state setup AND cross-service wiring both happen here:
       open files, allocate buffers, read DeviceConfig, resolve
       dependencies via emu_.Get<BarService>(), spawn worker threads. */
}
bool FooService::DoThing(int arg) { /* ... */ }

}
```

- **One service = one `.h` + one `.cpp` pair, OR one anonymous-namespaced `.cpp` with no public header.** Two shapes, picked by whether other TUs need to name the class:
    - **Shape S - public service, header + .cpp pair.** Used when consumers resolve this exact concrete via `emu_.Get<ThisType>()` (for example `Mmu`, `JitRunner`, `EmulatedMemory`, `PeripheralDispatcher`, abstract bases like `BoardContext` / `PageTableBuilder`). Filename is the snake_case of the class name exactly: `FooService` → `foo_service.{h,cpp}`. No sidecars (`foo_impl.cpp`, `foo_helpers.cpp`, `foo_internal.h`, …) and no method-body bleed into other modules.
    - **Shape P - private concrete, .cpp only, class inside `namespace { ... }`.** Used for every concrete that registers via `REGISTER_SERVICE_AS(Concrete, Base)` (consumers depend on `Base`, never on `Concrete`) AND for any concrete registered via `REGISTER_SERVICE` whose name is needed *only* by the registration macro itself. That is typical of peripherals that self-register with `PeripheralDispatcher` in `OnReady` and are then routed to by address, never resolved by class name. The class definition, all method bodies, and the `REGISTER_SERVICE[_AS]` line live in the same `.cpp`. The class sits inside `namespace { ... }` so no other TU can name it, and its enclosing `.cpp` has no companion header. This enforces the Dependency Inversion mechanically - there is no symbol available to import.
  A split of one service across two `.cpp` files is forbidden under either shape. If the file approaches the 500-line cap, the only sanctioned response is to split into multiple smaller services with distinct responsibilities (each its own `foo_*_service.{h,cpp}` or `foo_*.cpp`), never to spread one service across two `.cpp` files.
- **Three orthogonal per-impl trees, picked by what the thing IS:**
    - `libCerfCore/src/socs/<chip>/` - on-die silicon for one SoC family. `*PageTableBuilder`, every chip-level peripheral (UART, INTC, GPIO, RTC, timer, watchdog, memctrl, LCD controller, NAND controller, …). Concretes' `ShouldRegister` evaluates `emu_.Get<BoardContext>().GetSocId() == SocId::X`. Shape S allowed for cross-TU base concretes. Shape P more common for peripherals.
    - `libCerfCore/src/boards/<family>/` - one board family. The directory holds the `BoardContext` impl, board-only virtual peripherals (host-emulator notification channels, virtual DMA transports), and BSP-specific configuration writers (BSP_ARGS layout). The `ShouldRegister` of a concrete evaluates `emu_.Get<BoardContext>().GetBoardFamilyId() == BoardFamilyId::X`.
    - `libCerfCore/src/peripherals/<vendor>_<part>/` - off-chip silicon any board can connect (for example `cirrus_pd6710/` PCMCIA controller, `amd_am29lv800bb/` NOR flash). Concretes' `ShouldRegister` evaluates a family list - `auto f = emu_.Get<BoardContext>().GetBoardFamilyId(); return f == BoardFamilyId::X || f == BoardFamilyId::Y;`. The list grows when a new family adopts the same part. The file is never duplicated. The `libCerfCore/src/peripherals/` root also holds the abstract `Peripheral` base (`peripheral_base.{h,cpp}`) and the MMIO router (`peripheral_dispatcher.{h,cpp}`) - all peripheral-domain code, framework + concretes, lives in this one tree.
  Abstract bases (`BoardContext`, `PageTableBuilder`, `Peripheral`) live next to their consumers (`libCerfCore/src/boards/`, `libCerfCore/src/core/`, `libCerfCore/src/cpu/`, `libCerfCore/src/peripherals/`), not under any per-impl tree. The addition or removal of a chip / board / vendor-part touches exactly one directory. A split of one impl's pieces across multiple trees (chip pieces in board dir, board pieces in chip dir) is the wrong axis.
- **Before you write a new concrete, list that tree's root.** The base it implements is usually already there. A sibling concrete shows the idiom, but it does not name the seam.
- **Find an existing impl by enumerating the trees, not by keyword search.** CERF names off-chip parts by vendor and part number, and SoC units by chip. A grep for what the part does ("flash", "nor", "timer") therefore finds nothing, and you write a duplicate. `ls` the directories and files under `libCerfCore/src/peripherals/`, `libCerfCore/src/socs/`, and sometimes `libCerfCore/src/boards/`, and read the names. When `libCerfCore/src/socs/` carries a per-chip directory for each family member next to a shared one, that split is itself the signal: `ls` inside each and see whether a shared `*_impl.h` base or a sibling concrete already covers your unit.
- **A new device seam is the signal to search for the existing one.** Before you write a `virtual` interface for a device-facing seam, search for the base that already covers it. An existing base carries obligations that an invented one omits. Those obligations surface long after the duplication does.
- **`OnReady` is the setup lifecycle phase.** There is no `OnInit`. All setup - self-state, cross-service wiring, worker threads - happens in `OnReady`. Inside `OnReady`, a call to `emu_.Get<Other>()` runs `Other::OnReady` first if it has not run yet (lazy `EnsureReady()` on `Get<>`). The framework dependency-orders services on demand. Declaration order in the registry does not matter. Cycles (`A.OnReady` → `Get<B>` → `B.OnReady` → `Get<A>`) halt loudly. `EnsureReady` serializes concurrent first-callers on a mutex, so `OnReady` runs at most once.
- **Services have a shutdown phase, not only `OnReady`.** The framework runs `OnShutdown()` on every service that became ready (idempotently, reverse-registration order) before any service destructor begins. Use it to stop your own worker threads and detach from peers ONLY - continue to free a buffer a peer thread can read in the destructor, because during the shutdown phase a peer whose `OnShutdown` runs later has not stopped its thread yet. If you stop a worker thread in the destructor instead of `OnShutdown`, that thread can touch a peer already torn down.
- **Strategy pattern - `REGISTER_SERVICE_AS(Impl, Base)`** for device-version-dependent implementations. One impl per device ID, selected at startup by `DeviceConfig`. Zero `if (os_major == X)` branches inside a strategy - strategies ARE the version distinction (see `rules.md`).
- **`ShouldRegister()`** - return `false` to skip registration for the current device (for example a CE-7-only service on a WM5 device).

### What does NOT belong in a service

- Free functions that take `ServiceA&, ServiceB&, ServiceC&` as parameters. If a function needs services, it IS a method on the service that owns the responsibility.
- Statics and globals that hold service state. Zero tolerance.
- Process-wide singletons. `CerfEmulator` can run multi-instance. Each instance owns its own services.

### Writing a subsystem strategy (device-dependent implementation)

When a subsystem's behavior must differ between SoCs / boards / off-chip parts, the single uniform pattern is: **each candidate implementation is a Service whose `ShouldRegister()` queries `BoardContext` and returns `true` only when its own chip / board matches.** No `if (os_major == X)` branches anywhere - strategies ARE the version distinction.

This takes two shapes, and the shape depends on whether the service has external callers:

#### Shape A - standalone, no external callers → no base class, `REGISTER_SERVICE`

If the service has no methods any other code needs to call - it only configures its own thing (registers callbacks, populates a guest-visible table, starts an emulated peripheral) - there is no reason to invent a base class. Register it as a concrete service. Nobody ever resolves it.

```cpp
class S3C2410FooPeripheral : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        /* register MMIO handlers / interrupt source / etc. */
    }
};
REGISTER_SERVICE(S3C2410FooPeripheral);
```

A sibling file `pxa27x_foo_peripheral.cpp` whose `ShouldRegister` evaluates `SocId::Pxa270` is the second variant, and so on. The addition of a third variant touches no existing files.

#### Shape B - external callers exist → base class + `REGISTER_SERVICE_AS`

If other services need to call into this one, consumers must depend on an interface, not on any specific impl. Declare a pure-virtual base that derives from `Service`, put each concrete impl in its own file, and register each with `REGISTER_SERVICE_AS(Impl, Base)`. Consumer code calls `emu.Get<Base>()`. The winning impl (chosen by `ShouldRegister()`) is the one it returns.

Example:

```cpp
/* page_table_builder.h - abstract base. */
class PageTableBuilder : public Service {
public:
    using Service::Service;
    virtual uint32_t InitStackTopPa() const = 0;
    virtual uint32_t VaToPa(uint32_t va) const = 0;
    /* ... */
};

/* samsung_smdk2410_page_table_builder.cpp - one concrete impl. */
class SamsungSmdk2410PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardFamilyId() == BoardFamilyId::SamsungSmdk2410;
    }

    uint32_t InitStackTopPa() const override { /* SMDK2410 DRAM top */ }
    uint32_t VaToPa(uint32_t va) const override { /* SMDK2410 OEMAddressTable mapping */ }
};
REGISTER_SERVICE_AS(SamsungSmdk2410PageTableBuilder, PageTableBuilder);
```

Consumers always write `emu.Get<PageTableBuilder>()`. They do not know which concrete answered.

#### Rules that apply to both shapes

- **Exactly one impl wins for a required base.** Two `ShouldRegister` that return `true` for the same base is a bug. Two that return `false` for a required base is also a bug. `BoardContext` is the gate - the configured `board_id` (`cerf.json board.id` / `--board-id`) selects exactly one `BoardContext`, whose `GetBoardFamilyId()` / `GetBoardId()` / `GetSocId()` then bucket every other strategy. Optional bases (a peripheral that not every board has) can have zero winners - consumers use `emu.TryGet<Base>()` and tolerate absence.
- **`ShouldRegister` can resolve any service via `emu_.Get<>()`** - same lazy/recursive shape as `OnReady`. The framework defers slot resolution until first `Get<>` and walks each candidate's `ShouldRegister` on demand, so a strategy whose decision depends on another service (for example "register this MMU policy iff `Get<BoardContext>().GetSocId() == SocId::S3c2410`") composes cleanly. Cycles (`A.ShouldRegister` → `Get<B>` → `B.ShouldRegister` → `Get<A>`) halt loudly. NEVER reach into a specific concrete subclass by name. That is a Dependency Inversion violation. Depend on the abstract `Base` only.
- **Never put `if (board == X)` or `if (soc == X)` inside the impl body.** The impl already represents one specific board / SoC. That branch belongs in `ShouldRegister` and nowhere else. If two boards share most of an impl and diverge in one method, the divergence goes into a separate Service that the shared impl resolves via `emu_.Get<>()` - not an inline branch.
- **A shared-capable ISA capability goes in the shared path behind a `ProcessorConfig::HasX()` flag, never localized in one SoC's strategy.** When an instruction-set capability (VFP, NEON, DSP, …) currently appears on only one implemented SoC, its decode/dispatch still belongs in the shared decoder / emit path. A capability flag that the engine setup carries gates it (`ArmFeatures` / `MipsFeatures`). It must never be hardcoded into that SoC's coprocessor model (`ArmCoprocProvider` / `MipsCp0Model`) or strategy. "Only one current SoC has it" is an artifact of the implemented-SoC set, not a property of the capability, and a localization of it forces an expensive later re-extraction into the shared path.
- **One concrete per file, filename matches the class name exactly.** `S3C2410FooPeripheral` → `s3c2410_foo_peripheral.{h,cpp}`, `PXA27xFooPeripheral` → `pxa27x_foo_peripheral.{h,cpp}`. Never gang two concretes into one file. Same strict naming rule as § Writing a service: snake_case of the full class name, no abbreviation, no rename, no dropped suffix. The 500-line cap and the "split into multiple services" rule apply identically here - if a concrete impl outgrows its file, split it into smaller services, not into sidecar `.cpp` files.
- **Intra-board per-ROM / per-version variation is a ROM-gated strategy service.** When one board's behavior must differ across its ROM generations (CE versions, firmware revisions) - for example CERF models bootloaders, and two bootloader versions write identical data at shifted offsets - model it as per-version strategy services (a base service + per-generation impls). Each impl's `ShouldRegister` reads the distinguishing fact *from the ROM*. Never an inline per-ROM `if`, never a sidecar (`cerf.json`/`meta`) or whole-image-CRC gate. The only legitimate CE/OS-version source is the kernel's subsystem version read from the loaded ROM (available to every service). The gate is a fingerprint that matches every ROM of that generation, so a new ROM of a known generation Just Works. **Boundary condition (the approach's own fail case):** a per-version *seed* substituted for the bootloader's output is legitimate ONLY when the OEM shipped a small, enumerable set of generations. If an OEM shipped many ROMs per generation, the seeded data cannot be enumerated by version, and CERF must model or execute the bootloader itself instead. Flag this boundary, and do not assume. This pattern is the home for per-ROM-within-a-board variation, which the three-tree (board / SoC / off-chip-part) model has no default slot for.

## Qt Quick and QML

These rules apply to every QML file of the Qt frontend and to the C++ that configures Qt Quick.

- **The CERF style owns the look of every control.** The frontend runs the custom style `CerfStyle` (`cerf-qt/CerfStyle/`). Material is the fallback of that style. The look of a control has one owner: the file of that control in the style, which every instance gets. A variant that more than one view uses is one named component in the app module, and the views use it by name. A view never sets `background`, `contentItem`, `indicator`, a color or a font on a stock control.
- **A style file derives from the Material control of the same name, and changes only what CERF changes.** Import Material under a qualifier, and make the qualified type the root, for example `M.Button` in `Button.qml`. A style file never imports `QtQuick.Controls`, because the control then derives from itself. It never gives an `id` to a `background` or `contentItem` that it defines, because Qt then creates both the default item and the override. When a control creates another control inside it, replace both, for example `ScrollBar` and `ScrollView`.
- **Never copy a QML file of Qt into the tree.** Qt ships its style files under the LGPL or the GPL, and CERF ships under MIT. Derive from the Qt type, and override the property.
- **The global style configuration has one owner.** `qtquickcontrols2.conf` holds it. The C++ that starts the QML engine adds only the part that differs by host platform. A window or a view never sets `Material.theme`, `Material.accent`, `Material.primary` or `Material.background`. The `ApplicationWindow` of the style sets what applies to a whole window, so every top-level window is an `ApplicationWindow`.
- **Colors and font sizes come only from the `Theme` singleton of the style.** A color literal outside `Theme.qml` is a defect. So is a font size literal. A color of Material (`Material.accentColor`, `Material.hintTextColor`) is a token too.
- **Spacing, margins, paddings, radii and width breakpoints come from `Theme`.** A literal of one of them in a view is a defect, except 0. A dimension that one component alone owns, for example the size of its icon, is a named property of that component and appears once.
- **Repeated structure is one component.** Structure that more than one view shows, for example a page footer or a dialog frame, exists once as a component of the app module. A second view that needs it uses that component. A copy is a defect.
- **Layouts and anchors place items.** Use the `Layout` and `anchors` properties, and the paddings of a `Control`. A view never computes a position or a size from constants, as in `width: flick.width - 38`. A `Flickable` takes its content size from the `implicitHeight` of its content item.
- **A Qt signal name starts with a lowercase letter.** QML removes `on` from the name of a handler and changes the next letter to lowercase. QML then connects the handler to the signal of that name. As a result, a handler never reaches a signal whose name starts with an uppercase letter.
- **Copy a list from C++ before QML writes into its elements.** Qt 6.8.4 loses a write into an element of a `QVariantList` that a C++ method returned. Copy each element (`Object.assign({}, row)`), then write.
- **The frontend uses only the public API of Qt.** The Linux release runs on the Qt of each distribution, and Qt does not keep its private API stable between releases. A private class, a private header or a signal with a private argument type (`QQuickWindow::closing`) can make CERF fail to start on another Qt release. The Linux build also compiles QML to bytecode only, because Qt's QML compiler emits C++ that calls private API. The Qt targets on Linux compile with `-mno-direct-extern-access` (GCC) or `-fno-direct-access-external-data` (Clang). Some distributions build Qt so that a program must read Qt data through the library, not through a copy relocation (a copy of that data inside the program).

## When the Rule Breaks Down 

- You are about to introduce a static or global to hold service state, because the architecture will not let you avoid it. The architecture is wrong, not your code.
- You need to put logic somewhere and no existing service owns that responsibility, and the new service's name is unclear. Do not guess a name and create a file.
- You are about to bypass a CERF abstraction (storage overlay, OAL bridge, emulated peripheral) to call host directly because it "would be simpler". That is the symptom of a misshapen abstraction, not of a correct bypass.
- You are about to write code whose behavior you cannot state as a verifiable claim grounded in a chip datasheet, BSP source, architecture reference manual section, or runtime log
- A host caller seems to need to share host stateful subsystem with the guest and you cannot name a concrete CE app feature that requires the share. 

The cost of one question is one message. The cost of a wrong abstraction is hours of work to unwind it.
