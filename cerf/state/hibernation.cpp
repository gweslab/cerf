#include "hibernation.h"

#include "emulation_freeze.h"
#include "state_image_format.h"
#include "state_stream.h"

#include "../boot/rom_parser_service.h"
#include "../core/cerf_emulator.h"
#include "../core/cerf_paths.h"
#include "../core/device_config.h"
#include "../core/fatal.h"
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
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>

REGISTER_SERVICE(Hibernation);

void Hibernation::OnReady() {
    done_event_ = CreateEventW(nullptr, TRUE, TRUE, nullptr);
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

std::wstring Hibernation::DeviceDirFile(const wchar_t* name) const {
    const std::string dir = GetDeviceDir(emu_.Get<DeviceConfig>().device_name);
    return (std::filesystem::path(Utf8ToWide(dir.c_str())) / name).wstring();
}

std::wstring Hibernation::DefaultStatePath() const {
    return DeviceDirFile(kDefaultStateFile);
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

StateImageHeader Hibernation::LiveHeader() const {
    auto* rom = emu_.TryGet<RomParserService>();
    StateImageHeader h{};
    h.rom_entry_va      = (rom && rom->Ok()) ? rom->Primary().entry_va : 0;
    h.periph_layout_sig = PeripheralLayoutSig();
    uint64_t total = 0;
    if (rom) for (const auto& p : rom->Loaded()) total += p.raw.size();
    h.rom_total_bytes = total;
    h.guest_additions = emu_.Get<DeviceConfig>().guest_additions ? 1u : 0u;
    return h;
}

bool Hibernation::WriteImage(const std::wstring& path) {
    StateWriter w(path);
    if (!w.Ok()) return false;
    w.WriteRaw(kStateMagic, sizeof(kStateMagic));
    const StateImageHeader h = LiveHeader();
    w.Write("rom_entry_va", h.rom_entry_va);
    w.Write("periph_layout_sig", h.periph_layout_sig);
    w.Write("rom_total_bytes", h.rom_total_bytes);
    w.Write("guest_additions", h.guest_additions);

    for (const StateSection section : kStateSectionOrder) {
        w.BeginFrame(static_cast<uint32_t>(section));
        SaveSection(w, section);
        w.EndFrame();
    }
    return w.Ok() && w.Commit();
}

void Hibernation::SaveSection(StateWriter& w, StateSection section) {
    switch (section) {
        case StateSection::Cpu:   emu_.Get<GuestEngine>().SaveCpuState(w); break;
        case StateSection::Mmu:   emu_.Get<GuestEngine>().SaveMmuState(w); break;
        case StateSection::Ram:   emu_.Get<EmulatedMemory>().SaveState(w); break;
        case StateSection::Flash: emu_.Get<EmulatedMemory>().SaveFlashRegions(w); break;
        case StateSection::Periph: {
            const auto periphs = emu_.Get<PeripheralDispatcher>().RegisteredPeripherals();
            w.Write<uint32_t>("periph_count", static_cast<uint32_t>(periphs.size()));
            for (Peripheral* p : periphs) {
                w.BeginFrame(p->MmioBase());
                p->SaveState(w);
                w.EndFrame();
            }
            break;
        }
        case StateSection::Presentation: {
            auto& canvas = emu_.Get<HostCanvas>();
            w.Write<uint32_t>("surface_width", canvas.GuestSurfaceWidth());
            w.Write<uint32_t>("surface_height", canvas.GuestSurfaceHeight());
            break;
        }
        case StateSection::Widget: emu_.Get<HostWidgetRegistry>().SaveState(w); break;
        case StateSection::Reset:
            emu_.Get<GuestCpuReset>().SaveState(w);
            emu_.Get<GuestColdBoot>().SaveState(w);
            if (auto* c = emu_.TryGet<CerfVirtCustomizationsReset>())
                c->SaveState(w);
            break;
    }
}

bool Hibernation::Save(const std::wstring& path_in) {
    const std::wstring path = path_in.empty() ? DefaultStatePath() : path_in;
    auto& runner = emu_.Get<JitRunner>();

    emu_.Get<HostWindow>().ShowHwScreenTab(false);
    Progress("Saving state...");
    Progress("Saving RAM (%llu MB)...", static_cast<unsigned long long>(
        emu_.Get<EmulatedMemory>().VolatileByteCount() >> 20));

    runner.Pause();
    bool ok = false;
    {
        auto snap = emu_.Get<EmulationFreeze>().SnapshotSection();
        ok = WriteImage(path);
    }
    runner.Resume();

    Progress(ok ? "State saved." : "Save FAILED.");
    emu_.Get<HostWindow>().ShowHwScreenTab(true);

    if (ok) {
        const std::wstring png = DeviceDirFile(L"saved_state.png");
        emu_.Get<HostWindow>().RunOnUiThread([this, png] {
            emu_.Get<HostScreenshot>().SaveGuestSurfaceTo(png);
        });
    }
    return ok;
}

void Hibernation::ReadHeader(StateReader& r) {
    char magic[sizeof(kStateMagic)] = {};
    r.ReadRaw(magic, sizeof(magic));
    if (std::memcmp(magic, kStateMagic, sizeof(magic)) != 0) {
        const bool cerf = std::memcmp(magic, kStateMagic, sizeof(magic) - 1) == 0;
        throw StateImageRejected(cerf ? "the image uses another CERF state format"
                                      : "not a CERF state image");
    }
    StateImageHeader saved{};
    r.Read("rom_entry_va", saved.rom_entry_va);
    r.Read("periph_layout_sig", saved.periph_layout_sig);
    r.Read("rom_total_bytes", saved.rom_total_bytes);
    r.Read("guest_additions", saved.guest_additions);
    const StateImageHeader live = LiveHeader();
    if (saved.rom_entry_va != live.rom_entry_va || saved.rom_total_bytes != live.rom_total_bytes)
        throw StateImageRejected("the image is for a different ROM");
    if (saved.periph_layout_sig != live.periph_layout_sig)
        throw StateImageRejected("the image has a different peripheral set");
    if (saved.guest_additions != live.guest_additions)
        throw StateImageRejected(saved.guest_additions
                                     ? "the image was saved with guest additions"
                                     : "the image was saved without guest additions");
}

void Hibernation::RestorePeripherals(StateReader& r) {
    const auto periphs = emu_.Get<PeripheralDispatcher>().RegisteredPeripherals();
    uint32_t n = 0;
    r.Read("periph_count", n);
    if (n != periphs.size())
        r.Reject("the image has %u peripherals, this build has %zu", n, periphs.size());
    for (Peripheral* p : periphs) {
        const uint32_t base = r.EnterFrame();
        if (base != p->MmioBase())
            r.Reject("the image has peripheral 0x%08X where this build has 0x%08X",
                     base, p->MmioBase());
        p->RestoreState(r);
        r.LeaveFrame();
    }
    for (Peripheral* p : periphs) p->PostRestore();
}

void Hibernation::RestorePresentation(StateReader& r) {
    uint32_t w = 0, h = 0;
    r.Read("surface_width", w);
    r.Read("surface_height", h);
    if (w == 0 || h == 0) return;
    emu_.Get<HostWindow>().RunOnUiThread([this, w, h] {
        emu_.Get<HostCanvas>().SetGuestSurfaceSize(w, h);
        emu_.Get<HostWindow>().MatchGuestSize();
    });
}

void Hibernation::ApplyImage(StateReader& r, bool ram_only) {
    for (const StateSection section : kStateSectionOrder) {
        if (r.Remaining() == 0)
            r.Reject("section %u is missing from the image", static_cast<uint32_t>(section));
        const uint32_t id = r.EnterFrame();
        if (id != static_cast<uint32_t>(section))
            r.Reject("section %u where this build reads section %u", id,
                     static_cast<uint32_t>(section));
        if (ram_only && section != StateSection::Ram && section != StateSection::Flash) {
            r.SkipFrame();
            continue;
        }
        RestoreSection(r, section);
        r.LeaveFrame();
    }
    if (r.Remaining() != 0)
        r.Reject("the image carries %llu bytes past its last section",
                 static_cast<unsigned long long>(r.Remaining()));
}

void Hibernation::RestoreSection(StateReader& r, StateSection section) {
    switch (section) {
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
    }
}

void Hibernation::RollBack(const std::wstring& rollback_path) {
    StateReader r(rollback_path);
    try {
        if (!r.Ok()) throw StateImageRejected("the rollback image cannot be opened");
        ReadHeader(r);
        ApplyImage(r, false);
    } catch (const StateImageRejected& e) {
        emu_.Get<Fatal>().Die("Hibernation: the rollback image this build just wrote "
                              "was refused: %s", e.what());
    }
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
    auto snap = emu_.Get<EmulationFreeze>().SnapshotSection();
    bool ok = false;
    std::string reason;
    try {
        ReadHeader(r);
        const std::wstring rollback = DeviceDirFile(kRollbackStateFile);
        if (!WriteImage(rollback))
            throw StateImageRejected("the rollback image cannot be written");
        try {
            ApplyImage(r, ram_only);
            ok = true;
        } catch (const StateImageRejected&) {
            RollBack(rollback);
            DeleteFileW(rollback.c_str());
            throw;
        }
        DeleteFileW(rollback.c_str());
        emu_.Get<GuestEngine>().FlushTranslationCache();
    } catch (const StateImageRejected& e) {
        reason = e.what();
        emu_.Get<GuestEngine>().FlushTranslationCache();
    }
    snap.unlock();

    if (ok) {
        Progress("State restored.");
        if (!ram_only) emu_.Get<GuestDeepSleep>().OnFullRestore();
    } else {
        Progress("Restore refused: %s", reason.c_str());
        AwaitFailureAck(cold_boot_on_failure);
    }
    runner.Resume();

    emu_.Get<HostWindow>().ShowHwScreenTab(true);
    return ok;
}
