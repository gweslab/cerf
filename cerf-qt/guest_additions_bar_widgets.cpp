#include "bar_widget_source.h"
#include "customizations_editor.h"
#include "guest_resize_policy.h"
#include "task_manager_view.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/folder_share_config.h>
#include <cerfcore/host/machine_object.h>
#include <cerfcore/platform/host_path_name.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

class GuestAdditionsBarWidget final : public BarWidget {
public:
    GuestAdditionsBarWidget(cerfcore::CerfEmulator& emu, cerfcore::MachineObject& device) : emu_(emu), device_(device) {}

    std::string Name() const override { return device_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::GuestAdditions; }
    BarIcon     Icon() const override { return ResourceIcon{ResizeEnabled() ? "ga_autoresize" : "ga_autoresize_disabled"}; }

    std::string Tooltip() const override {
        if (!ResizeAvailable()) return "Guest Additions - click for tools";
        return ResizeEnabled() ? "Guest Additions - auto-resize ON (click to disable, right-click for tools)"
                               : "Guest Additions - auto-resize OFF (click to enable, right-click for tools)";
    }

    bool PrimaryClick() override {
        if (!ResizeAvailable()) return false;
        auto& policy = emu_.Get<GuestResizePolicy>();
        policy.SetEnabled(!policy.Enabled());
        return true;
    }

    std::vector<MenuItem> Menu() override {
        std::vector<MenuItem> items{MenuItem::Info("CERF Guest Additions"), MenuItem{}};
        if (emu_.TryGet<TaskManagerView>())
            items.push_back(MenuItem::Action("Task manager…", [this] { emu_.Get<TaskManagerView>().Show(); }));
        if (emu_.TryGet<CustomizationsEditor>())
            items.push_back(MenuItem::Action("Resolution / Customizations…",
                                             [this] { emu_.Get<CustomizationsEditor>().Open(); }));
        if (ResizeAvailable()) {
            const bool on = ResizeEnabled();
            items.push_back(MenuItem::Check("Resize guest to window", on,
                                            [this, on] { emu_.Get<GuestResizePolicy>().SetEnabled(!on); }));
        }
        if (items.back().label.empty()) items.pop_back();
        return items;
    }

    uint64_t RxCount() const override { return device_.RxCount(); }
    uint64_t TxCount() const override { return device_.TxCount(); }

private:
    bool ResizeAvailable() const {
        const GuestResizePolicy* policy = emu_.TryGet<GuestResizePolicy>();
        return policy != nullptr && policy->Available();
    }
    bool ResizeEnabled() const {
        const GuestResizePolicy* policy = emu_.TryGet<GuestResizePolicy>();
        return policy != nullptr && policy->Enabled();
    }

    cerfcore::CerfEmulator&  emu_;
    cerfcore::MachineObject& device_;
};

class SharedFolderBarWidget final : public BarWidget {
public:
    explicit SharedFolderBarWidget(cerfcore::CerfEmulator& emu) : emu_(emu) {}

    std::string Name() const override { return Folder().ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Storage; }
    BarIcon     Icon() const override { return FolderIcon{Folder().Enabled()}; }

    std::string Tooltip() const override {
        if (!Folder().Enabled()) return Name() + ": off - click to configure";
        return Name() + ": " + cerfcore::host_platform::HostLocationName(Folder().HostRoot());
    }

    std::vector<MenuItem> Menu() override {
        if (emu_.TryGet<CustomizationsEditor>() == nullptr) return {};
        return {MenuItem::Action("Configure shared folder…", [this] { emu_.Get<CustomizationsEditor>().Open(); })};
    }
    bool MenuIsOneAction() const override { return true; }

private:
    cerfcore::FolderShareConfig& Folder() const { return emu_.Get<cerfcore::FolderShareConfig>(); }

    cerfcore::CerfEmulator& emu_;
};

class GuestAdditionsBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        if (dynamic_cast<cerfcore::FolderShareConfig*>(&object)) return std::make_unique<SharedFolderBarWidget>(emu_);
        if (object.ObjectKind() == cerfcore::MachineObjectKind::kGuestAdditions)
            return std::make_unique<GuestAdditionsBarWidget>(emu_, object);
        return nullptr;
    }
};

}

REGISTER_SERVICE(GuestAdditionsBarWidgetSource);

}
