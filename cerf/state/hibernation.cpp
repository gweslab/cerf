#include "hibernation.h"

#include "emulation_freeze.h"
#include "state_image_format.h"
#include "state_stream.h"

#include "../boot/rom_parser_service.h"
#include "../core/cerf_emulator.h"
#include "../core/cerf_paths.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/string_utils.h"
#include "../cpu/emulated_memory.h"
#include "../host/host_canvas.h"
#include "../host/host_key_prompt.h"
#include "../host/host_screenshot.h"
#include "../host/guest_deep_sleep.h"
#include "../boot/guest_cold_boot.h"
#include "../host/host_widget_registry.h"
#include "../peripherals/cerf_virt/cerf_virt_customizations_reset.h"
#include "../socs/guest_cpu_reset.h"
#include "../host/host_window.h"
#include "../host/hw_screen.h"
#include "../jit/guest_engine.h"
#include "../jit/jit_runner.h"
#include "../peripherals/peripheral_base.h"
#include "../peripherals/peripheral_dispatcher.h"

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>

REGISTER_SERVICE(Hibernation);

void Hibernation::OnReady() {
    done_event_ = CreateEventW(nullptr, TRUE, TRUE, nullptr);  /* manual-reset, signaled */
    if (!done_event_) {
        LOG(Caution, "Hibernation: CreateEvent failed gle=%lu\n", GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

Hibernation::~Hibernation() {
    JoinWorker();
    if (done_event_) CloseHandle(done_event_);
}

void Hibernation::JoinWorker() {
    if (worker_.joinable()) worker_.join();
}

void Hibernation::SaveAsync(const std::wstring& path, std::function<void()> on_done) {
    JoinWorker();
    ResetEvent(done_event_);
    worker_ = std::thread([this, path, on_done = std::move(on_done)] {
        Save(path);
        SetEvent(done_event_);
        if (on_done) on_done();
    });
}

void Hibernation::RestoreAsync(const std::wstring& path, bool ram_only) {
    JoinWorker();
    ResetEvent(done_event_);
    worker_ = std::thread([this, path, ram_only] { Restore(path, ram_only); SetEvent(done_event_); });
}

void Hibernation::OnShutdown() {
    JoinWorker();
}

void Hibernation::Progress(const char* fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    emu_.Get<HwScreen>().AddLine(buf);
    LOG(Cerf, "[HIBERNATE] %s\n", buf);
}

void Hibernation::AwaitFailureAck(bool cold_boot) {
    Progress(cold_boot ? "Press any key for cold boot."
                       : "Press any key to resume.");
    auto& kp = emu_.Get<HostKeyPrompt>();
    kp.Arm();
    kp.Wait(INFINITE);
    kp.Disarm();
    Progress(cold_boot ? "Performing cold boot..." : "Resuming...");
}

std::wstring Hibernation::DefaultStatePath() const {
    /* The state image lives in the device directory - a property of the device,
       not of a parsed XIP ROM (a .sec NAND device loads no XIP, so RomParser has
       no Primary()). */
    const std::string dir = GetDeviceDir(emu_.Get<DeviceConfig>().device_name);
    return (std::filesystem::path(Utf8ToWide(dir.c_str())) / kDefaultStateFile)
        .wstring();
}

bool Hibernation::DefaultStateExists() const {
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(DefaultStatePath()), ec);
}

uint32_t Hibernation::PeripheralLayoutSig() const {
    const auto periphs = emu_.Get<PeripheralDispatcher>().RegisteredPeripherals();
    uint32_t sig = static_cast<uint32_t>(periphs.size());
    for (const Peripheral* p : periphs)
        sig = sig * 2654435761u + p->MmioBase();
    return sig;
}

void Hibernation::WriteHeader(StateWriter& w) const {
    auto* rom = emu_.TryGet<RomParserService>();
    StateImageHeader h{};
    std::memcpy(h.magic, kStateMagic, sizeof(h.magic));
    h.format_version    = kStateFormatVersion;
    h.rom_entry_va      = (rom && rom->Ok()) ? rom->Primary().entry_va : 0;
    h.periph_layout_sig = PeripheralLayoutSig();
    uint64_t total = 0;
    if (rom) for (const auto& p : rom->Loaded()) total += p.raw.size();
    h.rom_total_bytes = total;
    h.guest_additions = emu_.Get<DeviceConfig>().guest_additions ? 1u : 0u;
    w.Write(h);
}

bool Hibernation::ValidateHeader(StateReader& r) {
    StateImageHeader h{};
    r.Read(h);
    if (!r.Ok()) { Progress("State image truncated."); return false; }
    if (std::memcmp(h.magic, kStateMagic, sizeof(h.magic)) != 0) {
        Progress("Not a CERF state image."); return false;
    }
    if (h.format_version != kStateFormatVersion) {
        Progress("State image format v%u unsupported (need v%u).",
                 h.format_version, kStateFormatVersion);
        return false;
    }
    auto* rom = emu_.TryGet<RomParserService>();
    uint64_t total = 0;
    if (rom) for (const auto& p : rom->Loaded()) total += p.raw.size();
    const uint32_t entry = (rom && rom->Ok()) ? rom->Primary().entry_va : 0;
    if (h.rom_entry_va != entry || h.rom_total_bytes != total) {
        Progress("State image is for a different ROM - refusing."); return false;
    }
    if (h.periph_layout_sig != PeripheralLayoutSig()) {
        Progress("State image peripheral layout differs (incompatible build) - refusing.");
        return false;
    }
    const uint8_t ga = emu_.Get<DeviceConfig>().guest_additions ? 1u : 0u;
    if (h.guest_additions != ga) {
        Progress("State image saved %s guest additions - refusing.",
                 h.guest_additions ? "with" : "without");
        return false;
    }
    return true;
}

bool Hibernation::Save(const std::wstring& path_in) {
    const std::wstring path = path_in.empty() ? DefaultStatePath() : path_in;
    auto& runner = emu_.Get<JitRunner>();

    emu_.Get<HostWindow>().ShowHwScreenTab(false);
    Progress("Saving state...");

    runner.Pause();
    bool ok = false;
    {
        auto snap = emu_.Get<EmulationFreeze>().SnapshotSection();
        StateWriter w(path);
        if (w.Ok()) {
            WriteHeader(w);
            w.Write<uint32_t>(8u);   /* section count */

            auto section = [&w](StateSection id, const std::function<void()>& body) {
                const uint64_t hdr_off = w.BytesWritten();
                StateSectionHeader sh{ static_cast<uint32_t>(id), 0 };
                w.Write(sh);
                const uint64_t body_off = w.BytesWritten();
                body();
                const uint64_t len = w.BytesWritten() - body_off;
                w.PatchAt(hdr_off + offsetof(StateSectionHeader, length),
                          &len, sizeof(len));
            };

            section(StateSection::Cpu, [&] { emu_.Get<GuestEngine>().SaveCpuState(w); });
            section(StateSection::Mmu, [&] { emu_.Get<GuestEngine>().SaveMmuState(w); });

            const uint64_t ram = emu_.Get<EmulatedMemory>().VolatileByteCount();
            Progress("Saving RAM (%llu MB)...",
                     static_cast<unsigned long long>(ram >> 20));
            section(StateSection::Ram, [&] { emu_.Get<EmulatedMemory>().SaveState(w); });
            section(StateSection::Flash, [&] { emu_.Get<EmulatedMemory>().SaveFlashRegions(w); });

            section(StateSection::Periph, [&] {
                const auto periphs =
                    emu_.Get<PeripheralDispatcher>().RegisteredPeripherals();
                w.Write<uint32_t>(static_cast<uint32_t>(periphs.size()));
                for (Peripheral* p : periphs) {
                    w.Write<uint32_t>(p->MmioBase());
                    p->SaveState(w);
                }
            });

            section(StateSection::Presentation, [&] {
                auto& canvas = emu_.Get<HostCanvas>();
                w.Write<uint32_t>(canvas.GuestSurfaceWidth());
                w.Write<uint32_t>(canvas.GuestSurfaceHeight());
            });

            /* After Periph (GPIO/MCU state restored): re-driving from the
               restored widget then lands consistently. */
            section(StateSection::Widget, [&] {
                emu_.Get<HostWidgetRegistry>().SaveState(w);
            });

            section(StateSection::Reset, [&] {
                emu_.Get<GuestCpuReset>().SaveState(w);
                emu_.Get<GuestColdBoot>().SaveState(w);
                if (auto* c = emu_.TryGet<CerfVirtCustomizationsReset>())
                    c->SaveState(w);
            });
            ok = w.Ok() && w.Commit();
        }
    }
    runner.Resume();

    Progress(ok ? "State saved." : "Save FAILED.");
    /* Re-arm the framebuffer auto-switch so guest video returns on its
       next presented frame. */
    emu_.Get<HostWindow>().ShowHwScreenTab(true);

    if (ok) {
        const std::string dir =
            GetDeviceDir(emu_.Get<DeviceConfig>().device_name);
        const std::wstring png =
            (std::filesystem::path(Utf8ToWide(dir.c_str())) / L"saved_state.png")
                .wstring();
        emu_.Get<HostWindow>().RunOnUiThread([this, png] {
            emu_.Get<HostScreenshot>().SaveGuestSurfaceTo(png);
        });
    }
    return ok;
}

void Hibernation::RestorePeripherals(StateReader& r) {
    const auto periphs = emu_.Get<PeripheralDispatcher>().RegisteredPeripherals();
    uint32_t n = 0;
    r.Read(n);
    if (n != periphs.size()) {
        LOG(Caution, "Hibernation: peripheral count %u != live %zu\n",
            n, periphs.size());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    for (Peripheral* p : periphs) {
        uint32_t tag = 0;
        r.Read(tag);
        if (tag != p->MmioBase()) {
            LOG(Caution, "Hibernation: peripheral tag 0x%08X != live 0x%08X - desync\n",
                tag, p->MmioBase());
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        p->RestoreState(r);
    }
    /* All registers are in place; now re-assert the computed interrupt lines
       (source -> INTC -> JIT) that a single RestoreState can't establish. */
    for (Peripheral* p : periphs) p->PostRestore();
}

void Hibernation::RestorePresentation(StateReader& r) {
    uint32_t w = 0, h = 0;
    r.Read(w);
    r.Read(h);
    if (w == 0 || h == 0) return;
    /* Window/canvas resize is UI-thread only; marshal it. SetGuestSurfaceSize
       rebuilds the surface DIB, MatchGuestSize fits the window to it. */
    emu_.Get<HostWindow>().RunOnUiThread([this, w, h] {
        emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
        emu_.Get<HostWindow>().MatchGuestSize();
    });
}

bool Hibernation::Restore(const std::wstring& path_in, bool ram_only,
                          bool cold_boot_on_failure) {
    const std::wstring path = path_in.empty() ? DefaultStatePath() : path_in;
    auto& runner = emu_.Get<JitRunner>();

    emu_.Get<HostWindow>().ShowHwScreenTab(false);
    Progress(ram_only ? "Warm boot: restoring RAM..." : "Restoring state...");

    StateReader r(path);
    if (!r.Ok()) {
        Progress("Cannot open state image.");
        AwaitFailureAck(cold_boot_on_failure);
        emu_.Get<HostWindow>().ShowHwScreenTab(true);
        return false;
    }

    runner.Pause();
    /* Freeze peripheral worker threads so none mutates state mid-restore;
       released before AwaitFailureAck (an unbounded user-keypress wait). */
    auto snap = emu_.Get<EmulationFreeze>().SnapshotSection();
    bool ok = false;
    if (ValidateHeader(r)) {
        uint32_t nsections = 0;
        r.Read(nsections);
        for (uint32_t i = 0; i < nsections && r.Ok(); ++i) {
            StateSectionHeader sh{};
            r.Read(sh);
            if (!r.Ok()) break;
            const uint64_t body_start = r.Position();
            const StateSection sid = static_cast<StateSection>(sh.id);
            /* Warm boot keeps RAM and flash (both survive a reboot on real
               hardware) and re-inits the rest cold. */
            const bool apply = !ram_only ||
                sid == StateSection::Ram || sid == StateSection::Flash;
            if (apply) {
                switch (sid) {
                    case StateSection::Cpu:    emu_.Get<GuestEngine>().RestoreCpuState(r); break;
                    case StateSection::Mmu:    emu_.Get<GuestEngine>().RestoreMmuState(r); break;
                    case StateSection::Ram:    emu_.Get<EmulatedMemory>().RestoreState(r); break;
                    case StateSection::Flash:  emu_.Get<EmulatedMemory>().RestoreFlashRegions(r); break;
                    case StateSection::Periph: RestorePeripherals(r); break;
                    case StateSection::Presentation: RestorePresentation(r); break;
                    case StateSection::Widget: emu_.Get<HostWidgetRegistry>().RestoreState(r); break;
                    case StateSection::Reset:
                        emu_.Get<GuestCpuReset>().RestoreState(r);
                        emu_.Get<GuestColdBoot>().RestoreState(r);
                        if (auto* c = emu_.TryGet<CerfVirtCustomizationsReset>())
                            c->RestoreState(r);
                        break;
                    default: break;
                }
            }
            /* Re-align to the framed section end: skips a not-applied section
               and guards an asymmetric peripheral impl from desyncing. */
            r.SeekTo(body_start + sh.length);
        }
        emu_.Get<GuestEngine>().FlushTranslationCache();
        ok = r.Ok();
    }
    snap.unlock();

    if (ok) {
        Progress("State restored.");
        if (!ram_only) emu_.Get<GuestDeepSleep>().OnFullRestore();
    } else {
        /* Hold the CPU paused on the UART screen until the user acks the
           reason, then continue: a runtime load resumes the guest, a
           boot-time load falls through to a cold boot. */
        Progress("Restore FAILED.");
        AwaitFailureAck(cold_boot_on_failure);
    }
    runner.Resume();

    emu_.Get<HostWindow>().ShowHwScreenTab(true);
    return ok;
}
