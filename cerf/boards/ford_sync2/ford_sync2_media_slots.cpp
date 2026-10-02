#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/cerf_paths.h"
#include "../../core/string_utils.h"
#include "../../boards/board_context.h"
#include "ford_sync_2_id.h"
#include "../../socs/imx51/imx51_usboh3.h"
#include "../../host/host_widget_registry.h"
#include "../../host/host_icon_cache.h"
#include "../../host/host_window.h"
#include "../../core/fatal.h"
#include "ford_sync2_media_hub.h"
#include "ford_sync2_media_hub_sd_reader.h"

#include <commdlg.h>
#include <atomic>
#include <filesystem>

namespace {
class FordSync2MediaSlots : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::FordSync2;
    }

    class SlotWidget final : public HostWidget {
    public:
        SlotWidget(FordSync2MediaSlots& owner, int slot) : owner_(owner), slot_(slot) {}
        std::wstring WidgetName() const override { return slot_ == FordSync2MediaHub::kSdPort ? L"Media Hub SD" : L"Media Hub USB"; }
        WidgetGroup Group() const override { return WidgetGroup::Usb; }
        void DrawIcon(HDC dc, const RECT& box) const override {
            owner_.emu_.Get<HostIconCache>().DrawCentered(dc, box,
                slot_ == FordSync2MediaHub::kSdPort ? L"ICON_SD_MAP" : L"ICON_USB");
        }
        std::wstring Tooltip() const override { return WidgetName() + L": " + owner_.MediaName(slot_); }
        std::vector<WidgetMenuItem> BuildMenu() override { return owner_.Menu(slot_); }
        void RestoreWidgetState(StateReader&) override { ++owner_.generation_[slot_]; }
    private:
        FordSync2MediaSlots& owner_;
        int slot_;
    };

    void OnReady() override {
        controller_ = &emu_.Get<Imx51Usboh3>();
        auto locked = controller_->LockHostPort();
        auto& root = controller_->OtgHostRootPort();
        root.SetRestoreFactory([](uint32_t kind) -> std::unique_ptr<UsbDevice> {
            return kind == FordSync2MediaHub::kStateKind ? std::make_unique<FordSync2MediaHub>() : nullptr;
        });
        root.SetRequiresDevice();
        root.Attach(std::make_unique<FordSync2MediaHub>());
        for (int i = 0; i < FordSync2MediaHub::kPortCount; ++i) {
            for (const auto& media : Entries(i)) {
                if (!media.insert_on_launch) continue;
                auto device = Open(i, media);
                if (!device) {
                    LOG(Caution, "Media Hub: cannot open launch image '%s'\n", media.file.c_str());
                    continue;
                }
                Hub().SetMedia(i, std::move(device));
            }
            widgets_[i] = std::make_unique<SlotWidget>(*this, i);
            emu_.Get<HostWidgetRegistry>().Register(widgets_[i].get());
        }
    }

private:
    const std::vector<BundledUsbMedia>& Entries(int slot) const {
        const auto& cfg = emu_.Get<DeviceConfig>();
        return slot == FordSync2MediaHub::kSdPort ? cfg.bundled_sd_cards : cfg.bundled_usb_disks;
    }
    FordSync2MediaHub& Hub() const {
        auto* device = controller_->OtgHostRootPort().Device();
        if (!device || device->StateKind() != FordSync2MediaHub::kStateKind)
            emu_.Get<Fatal>().Die("Media Hub: the USB root port does not hold the Media Hub");
        return *static_cast<FordSync2MediaHub*>(device);
    }
    UsbMassStorageDevice* Current(int slot) const {
        return static_cast<UsbMassStorageDevice*>(Hub().Port(slot).Device());
    }
    std::unique_ptr<UsbMassStorageDevice> Open(int slot, const BundledUsbMedia& media) {
        std::unique_ptr<UsbMassStorageDevice> device;
        if (slot == FordSync2MediaHub::kSdPort) device = std::make_unique<FordSync2MediaHubSdReader>(media.cid);
        else device = std::make_unique<UsbMassStorageDevice>();
        const auto& cfg = emu_.Get<DeviceConfig>();
        if (!device->OpenImage(ResolveDeviceFile(cfg.device_name, media.file), media.name)) return {};
        return device;
    }
    std::wstring MediaName(int slot) const {
        auto locked = controller_->LockHostPort();
        auto* device = Current(slot);
        if (!device) return L"Empty";
        return Utf8ToWide(device->ImageName().c_str());
    }
    void Apply(int slot, uint64_t generation, const BundledUsbMedia* media) {
        const std::string path = media
            ? ResolveDeviceFile(emu_.Get<DeviceConfig>().device_name, media->file) : std::string();
        {
            auto locked = controller_->LockHostPort();
            if (generation_[slot] != generation) return;
            auto* current = Current(slot);
            const bool same_file = media && current && current->ImagePath() == path;
            if (same_file && (slot == FordSync2MediaHub::kUsbPort ||
                              static_cast<FordSync2MediaHubSdReader*>(current)->Cid() == media->cid))
                return;
            if (!media || same_file) {
                Hub().SetMedia(slot, {});
                generation = ++generation_[slot];
            }
        }
        if (!media) return;
        auto device = Open(slot, *media);
        if (!device) {
            const auto message = L"Cannot open existing media image: " + Utf8ToWide(media->file.c_str());
            MessageBoxW(emu_.Get<HostWindow>().Hwnd(), message.c_str(), L"Media Hub", MB_OK | MB_ICONERROR);
            return;
        }
        auto locked = controller_->LockHostPort();
        if (generation_[slot] != generation) return;
        Hub().SetMedia(slot, std::move(device));
        ++generation_[slot];
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
    std::unique_ptr<SlotWidget> widgets_[FordSync2MediaHub::kPortCount];
    std::atomic<uint64_t> generation_[FordSync2MediaHub::kPortCount]{};
};
}
REGISTER_SERVICE(FordSync2MediaSlots);
