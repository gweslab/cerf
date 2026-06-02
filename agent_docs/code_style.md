# Code Style

How to write code in CERF: file & symbol style, comments, logging, services
(the service-locator pattern, `REGISTER_SERVICE`, `OnReady`,
strategy pattern), the host/guest-state boundary, and when to stop and ask.
This page is MANDATORY and complements `rules.md` (behavioral rules) and
`subsystems.md` (what exists).

## File & Symbol Style

- **Headers declare, .cpp files implement.** Declaration and implementation live together: `foo.h` + `foo.cpp` in the same directory. Never forward-declare in one module's header and define in an unrelated module's .cpp.
- **500-line cap per .cpp/.h, enforced by the pre-commit hook. Going past the cap is NEVER permission to violate any other rule on this page.** The cap is a forcing function, not an escape hatch — if satisfying it appears to require breaking another rule (most commonly "One service = one `.h` + one `.cpp` pair" in § Services, or "No misc/grab-bag files" below), the design is wrong, not the rules. The only sanctioned response when a file approaches the limit is to split by responsibility — never by alphabet, method-prefix, "part 1 / part 2", or `_helpers` / `_extras` / `_impl` / `_internal` sidecars. **For services specifically, "split by responsibility" means splitting the service itself into multiple smaller services**, each with its own state, its own one-sentence responsibility, and its own `foo_service.{h,cpp}` pair following every rule in § Services. Spreading a single service across two `.cpp` files (or across a header and a sibling `.cpp` belonging to a different module) is forbidden regardless of how close to the cap the original file is. If you cannot describe the new responsibility boundary in one sentence per resulting service, you have not found the split — STOP and ask before writing code.
- **No misc/grab-bag files.** Never create `misc.cpp`, `helpers.cpp`, `extras.cpp`, `util2.cpp`. Every file's name describes a single responsibility.
- **Naming** — classes `PascalCase`, methods `PascalCase`, members `snake_case_`, free helpers `PascalCase`. Filenames `snake_case.{h,cpp}`.
- **Includes** — project headers with relative paths (`"../core/log.h"`), system headers with angle brackets. `#define NOMINMAX` before `<windows.h>` when windowsx/GDI identifiers would collide.
- **Don't reach past CERF's abstractions to call host APIs that CERF owns the answer to at runtime.** When the running guest can observe CERF's internal answer to a question (emulated peripheral state, virtual-platform behavior the guest depends on), host-side code must consult CERF's surface rather than asking the host directly — bypassing produces values the guest wasn't supposed to see. (This rule is about runtime guest-observable answers; it does not block bootstrap-time host file reads against the bundled tree.)

## Comments

- **Default: no comment.** Well-named identifiers explain the WHAT. Don't narrate what the next three lines do. This applies in every file type — YAML, MSBuild (`.vcxproj` / `.targets` / `.props`), PowerShell, batch, CMake — not just `.cpp` / `.h`. Multi-line essays above a one-line build step or a single cmdlet are slop; agents repeatedly exempt "build infrastructure" from the rule and they shouldn't.
- **Write a comment only when the WHY is non-obvious** — a hidden CE invariant, a subtle encoding, a workaround whose removal would break a specific app, a pointer-truncation hazard. Keep it short.
- **Never reference any document that isn't durably committed to the repo. Checklists (anything under `docs/ai_checklists/`) are additionally CONFIDENTIAL — they are private design material, not part of the public repo, and never will be. The `docs/ai_checklists/` path is `.gitignore`d, so `git stash` (with or without `-u`), `git diff`, and `git status` do not see those files; edits to a checklist survive every git operation transparently and any procedure that proposes to stash, stage, or diff a checklist change is incoherent — operate on checklists as plain disk files only.** Code that mentions a checklist's filename, section numbers (`§3.1`, `§7.2`, …), phase names, internal taxonomy, or any other design vocabulary lifted from it LEAKS the checklist to every reader of the public source. That is a confidentiality breach, separate from and on top of the rotting-reference problem. Tasks, PRs, tickets, agent-curated planning files, gitignored work-in-progress, scratch design docs, "the MPA design", "see the spec" all rot the same way; checklists rot AND breach confidentiality, so the prohibition is absolute and total. Forbidden examples (do not write, do not approximate, do not rephrase): `/* added for clipboard fix */`, `/* per checklist §3.1 */`, `/* see docs/ai_checklists/foo.md */`, `/* per the MPA design */`, `/* Step 11 of the spec */`, `/* see Phase 2 */`. References to durably-committed material (`agent_docs/rules.md`, `CLAUDE.md`, sibling source files in this repo, chip datasheet section numbers, BSP source paths) are fine. Test before adding: would a fresh developer at a fresh clone of this repo understand the WHY from this comment alone, with no checklist in hand? If yes, the comment stands; if no, inline the rationale or skip the comment.
- **Reference citations ARE comments.** Non-trivial peripheral / BSP behavior needs a comment naming the reference (chip datasheet section, BSP source path, ARM ARM section). A citation attached to code you did not actually read is fabrication.
- **No "removed X" / "TODO later" comments** for work that's actually done. If the code is gone, the comment is gone.
- **A comment that still makes sense moved to a random file is dead weight** — useful comments are glued to the specific code below them (non-obvious invariants, CE quirks, pointer-truncation hazards); generic narration ("lives in X", "moved to Y", "added for debugging", "out-of-line in Z") reads the same anywhere because it says nothing about what's actually there.

## Logging

- **Structured log channels** — `LOG(MEM, ...)`, `LOG(NET, ...)`, etc. One channel per subsystem. New subsystem → new channel in `log.h`, not a generic fallback. The exact set of channels is in flux during the v2 rewrite; align new code with whatever channels exist when you write it, and add a new one when no existing channel fits.
- **Default log mask is mode-gated.** Dev builds (`CERF_DEV_MODE=1`) enable every channel by default, so investigations have full output with no flag. Production builds (`CERF_DEV_MODE=0`) start with the mask cleared — only the always-on `Cerf` / `Caution` categories reach `cerf.log` until the user passes `--log=...`. The switch is the `Log::detail::enabled_mask` initializer in `cerf/core/log.cpp`.
- **Verbose LOG lines that print inputs/state are acceptable permanently — but only when low-frequency** — they are filtered by log level and aid future debugging at zero runtime cost when their fire-rate is low enough that the signal a future reader needs isn't buried in their noise. Anything firing per-clock, per-register-access, per-instruction, or per-context-switch is high-frequency and **must not ship in production**: either move it into a device-specific trace file under `cerf/tracing/<bundle>/` (gated by bundle CRC32, excluded from production builds), or wrap the LOG site in `#if CERF_DEV_MODE ... #endif` wherever a trace file doesn't apply. `build.ps1` sets `CERF_DEV_MODE=1` in dev and `CERF_DEV_MODE=0` in production. Per-clock UART register access logs are the cautionary tale: they once buried the actual UART TX bytes in `cerf.log` so badly that an agent had to build a separate script to reconstruct the TX stream. See `agent_docs/rules.md` § "Simple LOG verbose lines" for the full removal criteria.

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
    - **Shape S — public service, header + .cpp pair.** Used when consumers resolve this exact concrete via `emu_.Get<ThisType>()` (e.g. `Mmu`, `JitRunner`, `EmulatedMemory`, `PeripheralDispatcher`, abstract bases like `BoardDetector` / `MmuPolicy` / `PageTableBuilder`). Filename is the snake_case of the class name exactly: `FooService` → `foo_service.{h,cpp}`. No sidecars (`foo_impl.cpp`, `foo_helpers.cpp`, `foo_internal.h`, …) and no method-body bleed into other modules.
    - **Shape P — private concrete, .cpp only, class inside `namespace { ... }`.** Used for every concrete that registers via `REGISTER_SERVICE_AS(Concrete, Base)` (consumers depend on `Base`, never on `Concrete`) AND for any concrete registered via `REGISTER_SERVICE` whose name is needed *only* by the registration macro itself — typical of peripherals that self-register with `PeripheralDispatcher` in `OnReady` and are then routed to by address, never resolved by class name. The class definition, all method bodies, and the `REGISTER_SERVICE[_AS]` line live in the same `.cpp`. The class sits inside `namespace { ... }` so no other TU can name it; its enclosing `.cpp` has no companion header. This makes the Dependency Inversion mechanically enforced — there is literally no symbol available to import.
  Splitting one service across two `.cpp` files is forbidden under either shape. If the file approaches the 500-line cap, the only sanctioned response is to split into multiple smaller services with distinct responsibilities (each its own `foo_*_service.{h,cpp}` or `foo_*.cpp`), never to spread one service across two `.cpp` files.
- **Three orthogonal per-impl trees, picked by what the thing IS:**
    - `cerf/socs/<chip>/` — on-die silicon for one SoC family. `*PageTableBuilder`, `*MmuPolicy`, every chip-level peripheral (UART, INTC, GPIO, RTC, timer, watchdog, memctrl, LCD controller, NAND controller, …). Concretes' `ShouldRegister` checks `emu_.Get<BoardDetector>().GetSoc() == SocFamily::X`. Shape S allowed for cross-TU base concretes; Shape P more common for peripherals.
    - `cerf/boards/<board>/` — one specific OEM board / BSP. The `BoardDetector` impl (heuristically fingerprints the ROM bundle by a board-unique driver-blob signature), board-only virtual peripherals (host-emulator notification channels, virtual DMA transports), BSP-specific config writers (BSP_ARGS layout). Concretes' `ShouldRegister` checks `emu_.Get<BoardDetector>().GetBoard() == Board::X`.
    - `cerf/peripherals/<vendor>_<part>/` — off-chip silicon any board may wire up (e.g. `cirrus_pd6710/` PCMCIA controller, `amd_am29lv800bb/` NOR flash). Concretes' `ShouldRegister` checks a board-list — `auto b = emu_.Get<BoardDetector>().GetBoard(); return b == X || b == Y;`. The list grows when a new board adopts the same part; the file is never duplicated. The `cerf/peripherals/` root also holds the abstract `Peripheral` base (`peripheral_base.{h,cpp}`) and the MMIO router (`peripheral_dispatcher.{h,cpp}`) — all peripheral-domain code, framework + concretes, lives in this one tree.
  Abstract bases (`BoardDetector`, `PageTableBuilder`, `MmuPolicy`, `Peripheral`) live next to their consumers (`cerf/boards/`, `cerf/core/`, `cerf/cpu/`, `cerf/peripherals/`), not under any per-impl tree. Adding or removing a chip / board / vendor-part touches exactly one directory. Splitting one impl's pieces across multiple trees (chip pieces in board dir, board pieces in chip dir) is the wrong axis.
- **Dependencies via `emu_.Get<T>()`** — never cache service pointers in statics, globals, or construction-time copies. Captured references inside a method body are fine; captured at construction time is a service-locator bypass.
- **Single `OnReady` lifecycle phase.** There is no `OnInit`. All setup — self-state, cross-service wiring, worker threads — happens in `OnReady`. Inside `OnReady`, calling `emu_.Get<Other>()` runs `Other::OnReady` first if it hasn't yet (lazy `EnsureReady()` on `Get<>`). The framework dependency-orders services on demand; declaration order in the registry doesn't matter. Cycles (`A.OnReady` → `Get<B>` → `B.OnReady` → `Get<A>`) halt loudly via `ServiceInternal::HaltOnCycle`. `Get<>` is thread-safe; `EnsureReady` serializes concurrent first-callers on a mutex so `OnReady` runs at most once.
- **Strategy pattern — `REGISTER_SERVICE_AS(Impl, Base)`** for device-version-dependent implementations. One impl per device ID, selected at startup by `DeviceConfig`. Zero `if (os_major == X)` branches inside a strategy — strategies ARE the version distinction (see `rules.md`).
- **`ShouldRegister()`** — return `false` to skip registration for the current device (e.g. a CE-7-only service on a WM5 device).

### What does NOT belong in a service

- Free functions taking `ServiceA&, ServiceB&, ServiceC&` as parameters. If a function needs services, it IS a method on the service that owns the responsibility.
- Statics and globals holding service state. Zero tolerance.
- Process-wide singletons. `CerfEmulator` may run multi-instance; each instance owns its own services.

### Writing a subsystem strategy (device-dependent implementation)

When a subsystem's behavior must differ between SoCs / boards / off-chip parts, the single uniform pattern is: **each candidate implementation is a Service whose `ShouldRegister()` queries `BoardDetector` and returns `true` only when its own chip / board matches.** No `if (os_major == X)` branches anywhere — strategies ARE the version distinction.

The query axis matches the per-impl tree (see `subsystems.md` § "Per-chip / per-board / per-part strategies"):

- **SoC-family code** under `cerf/socs/<chip>/` — `ShouldRegister` checks `emu_.Get<BoardDetector>().GetSoc() == SocFamily::X`.
- **Board-specific code** under `cerf/boards/<board>/` — `ShouldRegister` checks `emu_.Get<BoardDetector>().GetBoard() == Board::X`.
- **Off-chip-part code** under `cerf/peripherals/<vendor>_<part>/` — `ShouldRegister` checks a board-list: `auto b = emu_.Get<BoardDetector>().GetBoard(); return b == X || b == Y;`.

There are two shapes this takes, depending on whether the service has external callers:

#### Shape A — standalone, no external callers → no base class, `REGISTER_SERVICE`

If the service has no methods any other code needs to call — it just wires up its own thing (registers callbacks, populates a guest-visible table, brings up an emulated peripheral) — there is no reason to invent a base class. Register as a concrete service; nobody ever resolves it.

```cpp
class S3C2410FooPeripheral : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    void OnReady() override {
        /* register MMIO handlers / interrupt source / etc. */
    }
};
REGISTER_SERVICE(S3C2410FooPeripheral);
```

A sibling file `pxa27x_foo_peripheral.cpp` whose `ShouldRegister` checks `SocFamily::PXA27x` is the second variant, and so on. Adding a third variant touches no existing files.

#### Shape B — external callers exist → base class + `REGISTER_SERVICE_AS`

If other services need to call into this one, consumers must depend on an interface, not on any specific impl. Declare a pure-virtual base that derives from `Service`, put each concrete impl in its own file, and register each with `REGISTER_SERVICE_AS(Impl, Base)`. Consumer code calls `emu.Get<Base>()`; the winning impl (chosen by `ShouldRegister()`) is what comes back.

Verified example — `cerf/socs/page_table_builder.h` + `cerf/socs/s3c2410/s3c2410_page_table_builder.cpp`:

```cpp
/* page_table_builder.h — abstract base. */
class PageTableBuilder : public Service {
public:
    using Service::Service;
    virtual uint32_t InitStackTopPa() const = 0;
    virtual uint32_t VaToPa(uint32_t va) const = 0;
    /* ... */
};

/* s3c2410_page_table_builder.cpp — one concrete impl. */
class S3C2410PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::S3C2410;
    }

    uint32_t InitStackTopPa() const override { /* S3C2410 DRAM top */ }
    uint32_t VaToPa(uint32_t va) const override { /* S3C2410 OEMAddressTable mapping */ }
};
REGISTER_SERVICE_AS(S3C2410PageTableBuilder, PageTableBuilder);
```

A sibling `pxa27x_page_table_builder.cpp` registers itself for `SocFamily::PXA27x` and so on. Consumers always write `emu.Get<PageTableBuilder>()` — they neither know nor care which concrete answered.

#### Rules that apply to both shapes

- **Exactly one impl wins for a required base.** Two `ShouldRegister` returning `true` for the same base is a bug; two returning `false` for a required base is also a bug. `BoardDetector` is the gate — its `GetSoc()` / `GetBoard()` answers come from heuristic ROM fingerprinting at boot, so each board lands in exactly one bucket. Optional bases (a peripheral that not every board has) may have zero winners — consumers use `emu.TryGet<Base>()` and tolerate absence.
- **`ShouldRegister` may resolve any service via `emu_.Get<>()`** — same lazy/recursive shape as `OnReady`. The framework defers slot resolution until first `Get<>` and walks each candidate's `ShouldRegister` on demand, so a strategy whose decision depends on another service (e.g. "register this MMU policy iff `Get<BoardDetector>().GetSoc() == SocFamily::S3C2410`") composes cleanly. Cycles (`A.ShouldRegister` → `Get<B>` → `B.ShouldRegister` → `Get<A>`) halt loudly. NEVER reach into a specific concrete subclass by name (e.g. `Smdk2410DevEmuDetector::Fingerprint`) — that's a Dependency Inversion violation; depend on the abstract `Base` only.
- **Never put `if (board == X)` or `if (soc == X)` inside the impl body.** The impl already represents one specific board / SoC; that branch belongs in `ShouldRegister` and nowhere else. If two boards share most of an impl and diverge in one method, the divergence goes into a separate Service that the shared impl resolves via `emu_.Get<>()` — not an inline branch.
- **A shared-capable ISA capability goes in the shared path behind a `ProcessorConfig::HasX()` flag, never localized in one SoC's strategy.** When an instruction-set capability (VFP, NEON, DSP, …) currently appears on only one implemented SoC, its decode/dispatch still belongs in the shared decoder / emit path gated by an `ArmProcessorConfig` capability flag, not hardcoded into that SoC's `CoprocEmitter` / strategy. "Only one current SoC has it" is an artifact of the implemented-SoC set, not a property of the capability, and localizing it forces an expensive later re-extraction into the shared path.
- **One concrete per file, filename matches the class name exactly.** `S3C2410FooPeripheral` → `s3c2410_foo_peripheral.{h,cpp}`, `PXA27xFooPeripheral` → `pxa27x_foo_peripheral.{h,cpp}`. Never gang two concretes into one file. Same strict naming rule as § Writing a service: snake_case of the full class name, no abbreviation, no rename, no dropped suffix. The 500-line cap and the "split into multiple services" rule apply identically here — if a concrete impl outgrows its file, split it into smaller services, not into sidecar `.cpp` files.

## When the Rule Breaks Down — Stop and Ask

- You're about to introduce a static or global to hold service state because the architecture won't let you avoid it. STOP and ask — the architecture is wrong, not your code.
- You need to put logic somewhere and no existing service owns that responsibility, and the new service's name is unclear. STOP and ask — don't guess a name and create a file.
- You're about to bypass a CERF abstraction (storage overlay, OAL bridge, emulated peripheral) to call host directly because it "would be simpler". STOP and ask — that's the symptom of the abstraction being misshapen, not of the bypass being correct.
- You're about to write code whose behavior you cannot state as a verifiable claim grounded in a chip datasheet, BSP source, ARM ARM section, or runtime log. STOP and ask — see `rules.md` § Mental Model Discipline.
- A host caller seems to need to share host stateful subsystem with the guest and you cannot name a concrete CE app feature that requires the share. STOP and ask — see § Internal State vs Host State.

The cost of asking is one message. The cost of a wrong abstraction is hours of unwinding.
