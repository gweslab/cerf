#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/cerf_paths.h"
#include "../../core/string_utils.h"
#include "../../boards/board_context.h"
#include "../../socs/imx51/imx51_usboh3.h"
#include "../../state/emulation_freeze.h"
#include "../../host/host_widget_registry.h"
#include "../../host/host_window.h"
#include "../../host/emulation_pause.h"
#include "../../jit/jit_runner.h"
#include "ford_sync2_media_hub.h"

#include <commdlg.h>
#include <atomic>
#include <filesystem>

namespace {
class FordSync2MediaHub : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::FordSyncGen2;
    }

    class SlotWidget final : public HostWidget {
    public:
        SlotWidget(FordSync2MediaHub& owner, int slot) : owner_(owner), slot_(slot) {}
        std::wstring WidgetName() const override { return slot_ == 0 ? L"Media Hub SD" : L"Media Hub USB"; }
        WidgetGroup Group() const override { return WidgetGroup::Usb; }
        bool PrimaryActionOpensMenu() const override { return true; }
        void DrawIcon(HDC dc, const RECT& box) const override { DrawChipIcon(dc, box); }
        std::wstring Tooltip() const override { return WidgetName() + L": " + owner_.MediaName(slot_); }
        std::vector<WidgetMenuItem> BuildMenu() override { return owner_.Menu(slot_); }
        void RestoreWidgetState(StateReader&) override { ++owner_.generation_[slot_]; }
    private:
        FordSync2MediaHub& owner_;
        int slot_;
    };

    void OnReady() override {
        controller_ = &emu_.Get<Imx51Usboh3>();
        auto frozen = emu_.Get<EmulationFreeze>().SnapshotSection();
        controller_->OtgHostRootPort().SetRestoreFactory([](uint32_t kind) -> std::unique_ptr<UsbDevice> {
            return kind == 4 ? std::make_unique<FordSync2UsbMediaHub>() : nullptr;
        });
        for (int i = 0; i < 2; ++i) {
            for (const auto& media : Entries(i)) {
                if (!media.insert_on_launch) continue;
                auto device = Open(i, media);
                if (!device) {
                    LOG(Caution, "Media Hub: cannot open launch image '%s'\n", media.file.c_str());
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
                EnsureHub().SetMedia(i, std::move(device));
            }
            widgets_[i] = std::make_unique<SlotWidget>(*this, i);
            emu_.Get<HostWidgetRegistry>().Register(widgets_[i].get());
        }
    }

private:
    const std::vector<BundledUsbMedia>& Entries(int slot) const {
        const auto& cfg = emu_.Get<DeviceConfig>();
        return slot == 0 ? cfg.bundled_sd_cards : cfg.bundled_usb_disks;
    }
    FordSync2UsbMediaHub* Hub() const {
        auto* device = controller_->OtgHostRootPort().Device();
        return device && device->StateKind() == 4 ? static_cast<FordSync2UsbMediaHub*>(device) : nullptr;
    }
    FordSync2UsbMediaHub& EnsureHub() {
        if (!Hub()) controller_->OtgHostRootPort().Attach(std::make_unique<FordSync2UsbMediaHub>());
        return *Hub();
    }
    std::unique_ptr<UsbMassStorageDevice> Open(int slot, const BundledUsbMedia& media) {
        std::unique_ptr<UsbMassStorageDevice> device;
        if (slot == 0) device = std::make_unique<FordSync2MediaHubSdReader>(media.cid);
        else device = std::make_unique<UsbMassStorageDevice>();
        const auto& cfg = emu_.Get<DeviceConfig>();
        if (!device->OpenImage(ResolveDeviceFile(cfg.device_name, media.file), media.name)) return {};
        return device;
    }
    std::wstring MediaName(int slot) const {
        auto frozen = emu_.Get<EmulationFreeze>().SnapshotSection();
        auto* hub = Hub();
        auto* device = hub ? hub->Port(slot).Device() : nullptr;
        if (!device) return L"Empty";
        return Utf8ToWide(static_cast<UsbMassStorageDevice*>(device)->ImageName().c_str());
    }
    void Apply(int slot, uint64_t generation, const BundledUsbMedia* media) {
        bool failed = false;
        auto& runner = emu_.Get<JitRunner>();
        const bool was_paused = emu_.Get<EmulationPause>().IsPaused();
        runner.Pause();
        {
            auto frozen = emu_.Get<EmulationFreeze>().SnapshotSection();
            if (generation_[slot] == generation) {
                auto* hub = Hub();
                auto* current = hub ? static_cast<UsbMassStorageDevice*>(hub->Port(slot).Device()) : nullptr;
                bool unchanged = false;
                if (media && current && current->ImagePath() ==
                    ResolveDeviceFile(emu_.Get<DeviceConfig>().device_name, media->file)) {
                    unchanged = slot == 1 || static_cast<FordSync2MediaHubSdReader*>(current)->Cid() == media->cid;
                    // Changing identity for the same exclusively opened image needs a reopen.
                    if (!unchanged) hub->SetMedia(slot, {});
                }
                if (!unchanged) {
                    auto device = media ? Open(slot, *media) : nullptr;
                    failed = media && !device;
                    if (!failed) {
                        if (media) EnsureHub().SetMedia(slot, std::move(device));
                        else if (hub) hub->SetMedia(slot, {});
                    }
                    ++generation_[slot];
                }
            }
        }
        if (!was_paused) runner.Resume();
        if (failed) {
            const auto message = L"Cannot open existing media image: " + Utf8ToWide(media->file.c_str());
            MessageBoxW(emu_.Get<HostWindow>().Hwnd(), message.c_str(), L"Media Hub", MB_OK | MB_ICONERROR);
        }
    }
    void Browse(int slot, uint64_t generation) {
        wchar_t file[MAX_PATH]{};
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = emu_.Get<HostWindow>().Hwnd();
        dialog.lpstrFilter = L"Disk images (*.img;*.bin;*.ima)\0*.img;*.bin;*.ima\0All files\0*.*\0";
        dialog.lpstrFile = file; dialog.nMaxFile = MAX_PATH;
        dialog.lpstrTitle = L"Choose existing media image";
        dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
        if (!GetOpenFileNameW(&dialog)) return;
        BundledUsbMedia media;
        media.file = WideToUtf8(file);
        media.name = WideToUtf8(std::filesystem::path(file).filename().wstring());
        Apply(slot, generation, &media);
    }
    std::vector<WidgetMenuItem> Menu(int slot) {
        const uint64_t generation = generation_[slot];
        std::vector<WidgetMenuItem> menu;
        WidgetMenuItem current; current.label = L"Current: " + MediaName(slot); current.enabled = false;
        menu.push_back(std::move(current));
        for (const auto& media : Entries(slot)) {
            WidgetMenuItem item; item.label = L"Insert " + Utf8ToWide(media.name.c_str());
            item.on_click = [this, slot, generation, media] { Apply(slot, generation, &media); };
            menu.push_back(std::move(item));
        }
        WidgetMenuItem browse; browse.label = L"Insert image...";
        browse.on_click = [this, slot, generation] { Browse(slot, generation); };
        menu.push_back(std::move(browse));
        WidgetMenuItem eject; eject.label = L"Eject";
        eject.on_click = [this, slot, generation] { Apply(slot, generation, nullptr); };
        menu.push_back(std::move(eject));
        return menu;
    }
    Imx51Usboh3* controller_ = nullptr;
    std::unique_ptr<SlotWidget> widgets_[2];
    std::atomic<uint64_t> generation_[2]{};
};
}
REGISTER_SERVICE(FordSync2MediaHub);
