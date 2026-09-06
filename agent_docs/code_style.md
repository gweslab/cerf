# Code Style

How to write code in CERF: file & symbol style, comments, logging, services
(the service-locator pattern, `REGISTER_SERVICE`, `OnReady`,
strategy pattern), the host/guest-state boundary, and when to stop and ask.
This page is MANDATORY and complements `rules.md` (behavioral rules) and
`subsystems.md` (what exists).

## File & Symbol Style

- **Headers declare, .cpp files implement.** Declaration and implementation live together: `foo.h` + `foo.cpp` in the same directory. Never forward-declare in one module's header and define in an unrelated module's .cpp.
- **500-line cap per source file (any language), enforced by the pre-commit hook. A file past the cap is NEVER permission to violate any other rule on this page.** The cap is a forcing function, not an escape hatch. If compliance with the cap appears to require a breach of another rule (most commonly "One service = one `.h` + one `.cpp` pair" in § Services, or "No misc/grab-bag files" below), the design is wrong, not the rules. When a file approaches the limit, the only sanctioned response is to split by responsibility - never by alphabet, method-prefix, "part 1 / part 2", or `_helpers` / `_extras` / `_impl` / `_internal` sidecars. **For services specifically, "split by responsibility" means a split of the service itself into multiple smaller services**, each with its own state, its own one-sentence responsibility, and its own `foo_service.{h,cpp}` pair that follows every rule in § Services. A single service spread across two `.cpp` files is forbidden, regardless of how close to the cap the original file is. The same holds for a spread across a header and a sibling `.cpp` that belongs to a different module. If you cannot describe the new responsibility boundary in one sentence per resulting service, you have not found the split - STOP and ask before you write code.
- **No misc/grab-bag files.** Never create `misc.cpp`, `helpers.cpp`, `extras.cpp`, `util2.cpp`. Every file's name describes a single responsibility.
- **Naming** - classes `PascalCase`, methods `PascalCase`, members `snake_case_`, free helpers `PascalCase`. Filenames `snake_case.{h,cpp}`.
- **Includes** - project headers with relative paths (`"../core/log.h"`), system headers with angle brackets. When windowsx/GDI identifiers collide, put `#define NOMINMAX` before `<windows.h>`.
- **Do not reach past CERF's abstractions to call host APIs that CERF owns the answer to at runtime.** When the running guest can observe CERF's internal answer to a question (emulated peripheral state, virtual-platform behavior the guest depends on), host-side code must consult CERF's surface and must not ask the host directly - a bypass produces values the guest was not supposed to see. (This rule is about runtime guest-observable answers. It does not block bootstrap-time host file reads against the bundled tree.)

## Comments

- **A comment is a CITATION, or it does not exist. There is no third kind.** A citation names the external source of truth for the code beneath it: a chip datasheet section, a CPU architecture manual section, a decompiled guest address with its ROM bundle name, a standard or RFC clause, or a permissively-licensed attributed source. That is the entire permitted set, and it is further bounded by `rules.md` § Reference Licence Hygiene - a source in that section's forbidden set is never cited here, whatever the citation would otherwise be worth. Everything else is forbidden - rationale, narration, restatement, design defense, alternatives history, background - as is any sentence that still reads fine with the code deleted. If you cannot name a source, write no comment. This applies in every file type, `.cpp` / `.h` / YAML / MSBuild / PowerShell / batch / CMake alike. Build infrastructure is not exempt.
- **Rationale is more dangerous than a wrong citation, not less.** A wrong citation dies the moment someone opens the reference. A confident wrong rationale is BELIEVED, and it outlives the code it defends. The urge to make the reader understand a hard decision is the tell that you are about to write one.
- **Default: no comment.** Well-named identifiers explain the WHAT. Do not narrate what the next three lines do.
- **Delete a non-citation comment your edit touches.** A reword or a revert keeps the prose.
- **Never reference any document that is not durably committed to the repo. Checklists (anything under `docs/ai_checklists/`) are additionally CONFIDENTIAL - they are private design material, not part of the public repo, and never will be. The `docs/ai_checklists/` path is `.gitignore`d, so `git stash` (with or without `-u`), `git diff`, and `git status` do not see those files. Edits to a checklist survive every git operation transparently, and any procedure that proposes to stash, stage, or diff a checklist change is incoherent - operate on checklists as plain disk files only.** Code that mentions a checklist's filename, section numbers (`§3.1`, `§7.2`, …), phase names, internal taxonomy, or any other design vocabulary lifted from it LEAKS the checklist to every reader of the public source. That is a confidentiality breach, separate from and on top of the rotting-reference problem. Tasks, PRs, tickets, agent-curated planning files, gitignored work-in-progress, scratch design docs, "the MPA design", "see the spec" all rot the same way. Checklists rot AND breach confidentiality, so the prohibition is absolute and total. Forbidden examples (do not write, do not approximate, do not rephrase): `/* added for clipboard fix */`, `/* per checklist §3.1 */`, `/* see docs/ai_checklists/foo.md */`, `/* per the MPA design */`, `/* Step 11 of the spec */`, `/* see Phase 2 */`. A reference to anything inside this project - a sibling source file, `agent_docs/`, `CLAUDE.md` - rots the same way and is not a citation either. A citation names a source OUTSIDE the project, from the permitted set in `rules.md` § Reference Licence Hygiene. Do this test before you add a comment: does a fresh developer at a fresh clone of this repo understand the WHY from this comment alone, with no checklist in hand? If yes, the comment stands. If no, inline the rationale or skip the comment.
- **Reference citations ARE comments.** Non-trivial peripheral behavior needs a comment that names the reference (chip datasheet section, architecture reference manual section, standard clause, decompiled guest address with its ROM bundle name, or a permitted open-source model per `rules.md` § Reference Licence Hygiene). A citation attached to code you did not actually read is fabrication.
- **No "removed X" / "TODO later" comments** for work that is actually done. If the code is gone, the comment is gone.
- **A comment that still makes sense moved to a random file is dead weight** - useful comments are glued to the specific code below them (non-obvious invariants, CE quirks, pointer-truncation hazards). Generic narration ("lives in X", "moved to Y", "added for debugging", "out-of-line in Z") reads the same anywhere, because it says nothing about what is actually there.

## Logging

- **A LOG line is a record of an event, not prose.** It carries the event and the values a reader needs to act on it (register, address, value, PC, function). Narration, rationale, design defence, apology, TODO text, and anything lifted from the session that produced the code are the same bloat that § Comments bans, and they are banned here for the same reason. This binds hardest on the `LOG` immediately before a `CerfFatalExit`, because that one line is what a user pastes back: it states what was hit and with which values, never an essay about why the path is unimplemented.
- **Structured log channels** - `LOG(MEM, ...)`, `LOG(NET, ...)`, and more. One channel per subsystem. New subsystem → new channel in `log.h`, not a generic fallback. The exact set of channels is in flux during the v2 rewrite. Align new code with whatever channels exist when you write it, and add a new one when no existing channel fits.
- **Default log mask is mode-gated.** Dev builds (`CERF_DEV_MODE=1`) enable every channel by default, so investigations have full output with no flag. Production builds (`CERF_DEV_MODE=0`) start with a limited default set: `Log::MASK_PRODUCTION_DEFAULT`, the always-on `Cerf` / `Caution` categories plus the event/milestone channels that stay non-spamming on every board. The user widens or narrows that set with `--log=...` / `--no-log=...`. The switch is the `Log::detail::enabled_mask` initializer in `cerf/core/log.cpp`.
- **Verbose LOG lines that print inputs/state are acceptable permanently - but only when low-frequency** - the log level filters them, and they aid future debugging at zero runtime cost. That holds when their fire-rate is low enough that the signal a future reader needs is not buried in their noise. Anything that fires per-clock, per-register-access, per-instruction, or per-context-switch is high-frequency and **must not ship in production**: either move it into a device-specific trace file under `cerf/tracing/<bundle>/` (gated by bundle CRC32, excluded from production builds), or wrap the LOG site in `#if CERF_DEV_MODE ... #endif` wherever a trace file does not apply. `build.ps1` sets `CERF_DEV_MODE=1` in dev and `CERF_DEV_MODE=0` in production. See `agent_docs/rules.md` § "Simple LOG verbose lines" for the full removal criteria.
- **`#if CERF_DEV_MODE` gates the dev-mode subsystem - it is NOT a catch-all for "debugging-ish" code, and this rule does not discourage diagnostics.** Diagnostics are essential. The rule is purely *where each kind lives*. Classify before you wrap anything:
  - **Temporary, tied to one bug hunt** (a register dump at one PC, a abort-walker trace, a thread-suspend dump): home is a CRC-gated trace file under `cerf/tracing/<bundle>/`, or deletion when the hunt ends - **never** `#if CERF_DEV_MODE` inside JIT/MMU/peripheral core, which launders throwaway debugging into code that looks permanent and pollutes the fragile core.
  - **Permanently useful, low-frequency operational log** (an event any maintainer wants on a dev *or* production run - an open-bus floating access, a touch into unmapped MMIO, a rare mode transition): a plain `LOG()`. A wrap in `#if CERF_DEV_MODE` is backwards - it deletes the log in production builds, exactly where the silent event it guards is most dangerous.
  - **Permanently useful but high-frequency** (per-clock / per-register / per-instruction): the *only* case `#if CERF_DEV_MODE` legitimately wraps in core - and even then a trace file is preferred (see the high-frequency-log rule above and in `agent_docs/rules.md`).

## Services

A **service** is a class owned by `CerfEmulator` via `ServiceRegistry`, accessed through `emu.Get<T>()`. All stateful, device-visible host-side behavior lives in a service. Free functions that take services as parameters are technical debt (see `rules.md`).

### Writing a service

```cpp
/* foo_service.h */
#pragma once
#include "../core/service.h"

class FooService : public Service {
public:
    explicit FooService(CerfEmulator& emu) : Service(emu) {}
    void OnReady() override;

    bool DoThing(int arg);
};

/* foo_service.cpp */
#include "foo_service.h"
REGISTER_SERVICE(FooService);

void FooService::OnReady() {
    /* self-state setup AND cross-service wiring both happen here:
       open files, allocate buffers, read DeviceConfig, resolve
       dependencies via emu_.Get<BarService>(), spawn worker threads. */
}
bool FooService::DoThing(int arg) { /* ... */ }
```

- **One service = one `.h` + one `.cpp` pair, OR one anonymous-namespaced `.cpp` with no public header.** Two shapes, picked by whether other TUs need to name the class:
    - **Shape S - public service, header + .cpp pair.** Used when consumers resolve this exact concrete via `emu_.Get<ThisType>()` (for example `Mmu`, `JitRunner`, `EmulatedMemory`, `PeripheralDispatcher`, abstract bases like `BoardContext` / `PageTableBuilder`). Filename is the snake_case of the class name exactly: `FooService` → `foo_service.{h,cpp}`. No sidecars (`foo_impl.cpp`, `foo_helpers.cpp`, `foo_internal.h`, …) and no method-body bleed into other modules.
    - **Shape P - private concrete, .cpp only, class inside `namespace { ... }`.** Used for every concrete that registers via `REGISTER_SERVICE_AS(Concrete, Base)` (consumers depend on `Base`, never on `Concrete`) AND for any concrete registered via `REGISTER_SERVICE` whose name is needed *only* by the registration macro itself. That is typical of peripherals that self-register with `PeripheralDispatcher` in `OnReady` and are then routed to by address, never resolved by class name. The class definition, all method bodies, and the `REGISTER_SERVICE[_AS]` line live in the same `.cpp`. The class sits inside `namespace { ... }` so no other TU can name it, and its enclosing `.cpp` has no companion header. This enforces the Dependency Inversion mechanically - there is no symbol available to import.
  A split of one service across two `.cpp` files is forbidden under either shape. If the file approaches the 500-line cap, the only sanctioned response is to split into multiple smaller services with distinct responsibilities (each its own `foo_*_service.{h,cpp}` or `foo_*.cpp`), never to spread one service across two `.cpp` files.
- **Three orthogonal per-impl trees, picked by what the thing IS:**
    - `cerf/socs/<chip>/` - on-die silicon for one SoC family. `*PageTableBuilder`, every chip-level peripheral (UART, INTC, GPIO, RTC, timer, watchdog, memctrl, LCD controller, NAND controller, …). Concretes' `ShouldRegister` evaluates `emu_.Get<BoardContext>().GetSoc() == SocFamily::X`. Shape S allowed for cross-TU base concretes. Shape P more common for peripherals.
    - `cerf/boards/<board>/` - one specific OEM board / BSP. The `BoardContext` impl (reports the board's `Board` / `SocFamily` / `CpuArch` / `RomPlacingMode`, and registers when the configured `board_id` names it), board-only virtual peripherals (host-emulator notification channels, virtual DMA transports), BSP-specific config writers (BSP_ARGS layout). Concretes' `ShouldRegister` evaluates `emu_.Get<BoardContext>().GetBoard() == Board::X`.
    - `cerf/peripherals/<vendor>_<part>/` - off-chip silicon any board can connect (for example `cirrus_pd6710/` PCMCIA controller, `amd_am29lv800bb/` NOR flash). Concretes' `ShouldRegister` evaluates a board-list - `auto b = emu_.Get<BoardContext>().GetBoard(); return b == X || b == Y;`. The list grows when a new board adopts the same part. The file is never duplicated. The `cerf/peripherals/` root also holds the abstract `Peripheral` base (`peripheral_base.{h,cpp}`) and the MMIO router (`peripheral_dispatcher.{h,cpp}`) - all peripheral-domain code, framework + concretes, lives in this one tree.
  Abstract bases (`BoardContext`, `PageTableBuilder`, `Peripheral`) live next to their consumers (`cerf/boards/`, `cerf/core/`, `cerf/cpu/`, `cerf/peripherals/`), not under any per-impl tree. The addition or removal of a chip / board / vendor-part touches exactly one directory. A split of one impl's pieces across multiple trees (chip pieces in board dir, board pieces in chip dir) is the wrong axis.
- **Before you write a new concrete, list that tree's root.** The base it implements is usually already there. A sibling concrete shows the idiom, but it does not name the seam.
- **Find an existing impl by enumerating the trees, not by keyword search.** CERF names off-chip parts by vendor and part number, and SoC units by chip. A grep for what the part does ("flash", "nor", "timer") therefore finds nothing, and you write a duplicate. `ls` the directories and files under `cerf/peripherals/`, `cerf/socs/`, and sometimes `cerf/boards/`, and read the names. When `cerf/socs/` carries a per-chip directory for each family member next to a shared one, that split is itself the signal: `ls` inside each and see whether a shared `*_impl.h` base or a sibling concrete already covers your unit.
- **A new device seam is the signal to search for the existing one.** Before you write a `virtual` interface for a device-facing seam, search for the base that already covers it. An existing base carries obligations that an invented one omits. Those obligations surface long after the duplication does.
- **Dependencies via `emu_.Get<T>()`** - never cache service pointers in statics, globals, or construction-time copies. Captured references inside a method body are fine. A reference captured at construction time is a service-locator bypass.
- **`OnReady` is the setup lifecycle phase.** There is no `OnInit`. All setup - self-state, cross-service wiring, worker threads - happens in `OnReady`. Inside `OnReady`, a call to `emu_.Get<Other>()` runs `Other::OnReady` first if it has not run yet (lazy `EnsureReady()` on `Get<>`). The framework dependency-orders services on demand. Declaration order in the registry does not matter. Cycles (`A.OnReady` → `Get<B>` → `B.OnReady` → `Get<A>`) halt loudly via `ServiceInternal::HaltOnCycle`. `Get<>` is thread-safe. `EnsureReady` serializes concurrent first-callers on a mutex, so `OnReady` runs at most once.
- **Services have a shutdown phase, not only `OnReady`.** The framework runs `OnShutdown()` on every service that became ready (idempotently, reverse-registration order) before any service destructor begins. Use it to stop your own worker threads and detach from peers ONLY - continue to free a buffer a peer thread can read in the destructor, because during the shutdown phase a peer whose `OnShutdown` runs later has not stopped its thread yet. If you stop a worker thread in the destructor instead of `OnShutdown`, that thread can touch a peer already torn down.
- **Strategy pattern - `REGISTER_SERVICE_AS(Impl, Base)`** for device-version-dependent implementations. One impl per device ID, selected at startup by `DeviceConfig`. Zero `if (os_major == X)` branches inside a strategy - strategies ARE the version distinction (see `rules.md`).
- **`ShouldRegister()`** - return `false` to skip registration for the current device (for example a CE-7-only service on a WM5 device).

### What does NOT belong in a service

- Free functions that take `ServiceA&, ServiceB&, ServiceC&` as parameters. If a function needs services, it IS a method on the service that owns the responsibility.
- Statics and globals that hold service state. Zero tolerance.
- Process-wide singletons. `CerfEmulator` can run multi-instance. Each instance owns its own services.

### Writing a subsystem strategy (device-dependent implementation)

When a subsystem's behavior must differ between SoCs / boards / off-chip parts, the single uniform pattern is: **each candidate implementation is a Service whose `ShouldRegister()` queries `BoardContext` and returns `true` only when its own chip / board matches.** No `if (os_major == X)` branches anywhere - strategies ARE the version distinction.

The query axis matches the per-impl tree (see `subsystems.md` § "Per-chip / per-board / per-part strategies"):

- **SoC-family code** under `cerf/socs/<chip>/` - `ShouldRegister` evaluates `emu_.Get<BoardContext>().GetSoc() == SocFamily::X`.
- **Board-specific code** under `cerf/boards/<board>/` - `ShouldRegister` evaluates `emu_.Get<BoardContext>().GetBoard() == Board::X`.
- **Off-chip-part code** under `cerf/peripherals/<vendor>_<part>/` - `ShouldRegister` evaluates a board-list: `auto b = emu_.Get<BoardContext>().GetBoard(); return b == X || b == Y;`.

This takes two shapes, and the shape depends on whether the service has external callers:

#### Shape A - standalone, no external callers → no base class, `REGISTER_SERVICE`

If the service has no methods any other code needs to call - it only configures its own thing (registers callbacks, populates a guest-visible table, starts an emulated peripheral) - there is no reason to invent a base class. Register it as a concrete service. Nobody ever resolves it.

```cpp
class S3C2410FooPeripheral : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    void OnReady() override {
        /* register MMIO handlers / interrupt source / etc. */
    }
};
REGISTER_SERVICE(S3C2410FooPeripheral);
```

A sibling file `pxa27x_foo_peripheral.cpp` whose `ShouldRegister` evaluates `SocFamily::PXA27x` is the second variant, and so on. The addition of a third variant touches no existing files.

#### Shape B - external callers exist → base class + `REGISTER_SERVICE_AS`

If other services need to call into this one, consumers must depend on an interface, not on any specific impl. Declare a pure-virtual base that derives from `Service`, put each concrete impl in its own file, and register each with `REGISTER_SERVICE_AS(Impl, Base)`. Consumer code calls `emu.Get<Base>()`. The winning impl (chosen by `ShouldRegister()`) is the one it returns.

Verified example - `cerf/boards/page_table_builder.h` + `cerf/boards/smdk2410_devemu/smdk2410_devemu_page_table_builder.cpp`:

```cpp
/* page_table_builder.h - abstract base. */
class PageTableBuilder : public Service {
public:
    using Service::Service;
    virtual uint32_t InitStackTopPa() const = 0;
    virtual uint32_t VaToPa(uint32_t va) const = 0;
    /* ... */
};

/* smdk2410_devemu_page_table_builder.cpp - one concrete impl. */
class Smdk2410DevEmuPageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }

    uint32_t InitStackTopPa() const override { /* SMDK2410 DRAM top */ }
    uint32_t VaToPa(uint32_t va) const override { /* SMDK2410 OEMAddressTable mapping */ }
};
REGISTER_SERVICE_AS(Smdk2410DevEmuPageTableBuilder, PageTableBuilder);
```

A sibling `jornada720_page_table_builder.cpp` registers itself for `Board::Jornada720` and so on. Consumers always write `emu.Get<PageTableBuilder>()` - they neither know nor care which concrete answered. (`PageTableBuilder` is the VA→PA map, a per-board choice, so its concretes select on `GetBoard()`. A SoC-family strategy like `ArmProcessorConfig` selects on `GetSoc()` instead.)

#### Rules that apply to both shapes

- **Exactly one impl wins for a required base.** Two `ShouldRegister` that return `true` for the same base is a bug. Two that return `false` for a required base is also a bug. `BoardContext` is the gate - the configured `board_id` (`cerf.json board.id` / `--board-id`) selects exactly one `BoardContext`, whose `GetBoard()` / `GetSoc()` then bucket every other strategy. Optional bases (a peripheral that not every board has) can have zero winners - consumers use `emu.TryGet<Base>()` and tolerate absence.
- **`ShouldRegister` can resolve any service via `emu_.Get<>()`** - same lazy/recursive shape as `OnReady`. The framework defers slot resolution until first `Get<>` and walks each candidate's `ShouldRegister` on demand, so a strategy whose decision depends on another service (for example "register this MMU policy iff `Get<BoardContext>().GetSoc() == SocFamily::S3C2410`") composes cleanly. Cycles (`A.ShouldRegister` → `Get<B>` → `B.ShouldRegister` → `Get<A>`) halt loudly. NEVER reach into a specific concrete subclass by name (for example `Smdk2410DevEmuDetector::Fingerprint`) - that is a Dependency Inversion violation. Depend on the abstract `Base` only.
- **Never put `if (board == X)` or `if (soc == X)` inside the impl body.** The impl already represents one specific board / SoC. That branch belongs in `ShouldRegister` and nowhere else. If two boards share most of an impl and diverge in one method, the divergence goes into a separate Service that the shared impl resolves via `emu_.Get<>()` - not an inline branch.
- **A shared-capable ISA capability goes in the shared path behind a `ProcessorConfig::HasX()` flag, never localized in one SoC's strategy.** When an instruction-set capability (VFP, NEON, DSP, …) currently appears on only one implemented SoC, its decode/dispatch still belongs in the shared decoder / emit path, gated by the engine's processor-config capability flag (`ArmProcessorConfig` / `MipsProcessorConfig` `HasX()`). It must never be hardcoded into that SoC's coprocessor emitter (`CoprocEmitter` / `MipsCp0Emitter`) or strategy. "Only one current SoC has it" is an artifact of the implemented-SoC set, not a property of the capability, and a localization of it forces an expensive later re-extraction into the shared path.
- **One concrete per file, filename matches the class name exactly.** `S3C2410FooPeripheral` → `s3c2410_foo_peripheral.{h,cpp}`, `PXA27xFooPeripheral` → `pxa27x_foo_peripheral.{h,cpp}`. Never gang two concretes into one file. Same strict naming rule as § Writing a service: snake_case of the full class name, no abbreviation, no rename, no dropped suffix. The 500-line cap and the "split into multiple services" rule apply identically here - if a concrete impl outgrows its file, split it into smaller services, not into sidecar `.cpp` files.
- **Intra-board per-ROM / per-version variation is a ROM-gated strategy service.** When one board's behavior must differ across its ROM generations (CE versions, firmware revisions) - for example CERF models bootloaders, and two bootloader versions write identical data at shifted offsets - model it as per-version strategy services (a base service + per-generation impls). Each impl's `ShouldRegister` reads the distinguishing fact *from the ROM*. Never an inline per-ROM `if`, never a sidecar (`cerf.json`/`meta`) or whole-image-CRC gate. The only legitimate CE/OS-version source is the kernel's subsystem version read from the loaded ROM (available to every service). The gate is a fingerprint that matches every ROM of that generation, so a new ROM of a known generation Just Works. **Boundary condition (the approach's own fail case):** a per-version *seed* substituted for the bootloader's output is legitimate ONLY when the OEM shipped a small, enumerable set of generations. If an OEM shipped many ROMs per generation, the seeded data cannot be enumerated by version, and CERF must model or execute the bootloader itself instead. Flag this boundary, and do not assume. This pattern is the home for per-ROM-within-a-board variation, which the three-tree (board / SoC / off-chip-part) model has no default slot for.

## When the Rule Breaks Down - Stop and Ask

- You are about to introduce a static or global to hold service state, because the architecture will not let you avoid it. STOP and ask - the architecture is wrong, not your code.
- You need to put logic somewhere and no existing service owns that responsibility, and the new service's name is unclear. STOP and ask - do not guess a name and create a file.
- You are about to bypass a CERF abstraction (storage overlay, OAL bridge, emulated peripheral) to call host directly because it "would be simpler". STOP and ask - that is the symptom of a misshapen abstraction, not of a correct bypass.
- You are about to write code whose behavior you cannot state as a verifiable claim grounded in a chip datasheet, BSP source, architecture reference manual section, or runtime log. STOP and ask - see `rules.md` § Mental Model Discipline.
- A host caller seems to need to share host stateful subsystem with the guest and you cannot name a concrete CE app feature that requires the share. STOP and ask - see § Internal State vs Host State.

The cost of one question is one message. The cost of a wrong abstraction is hours of work to unwind it.
