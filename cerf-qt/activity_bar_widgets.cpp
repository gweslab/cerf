#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_object.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

class ActivityBarWidget final : public BarWidget {
public:
    ActivityBarWidget(cerfcore::MachineObject& object, BarGroup group, std::string icon, std::string tooltip)
        : object_(object), group_(group), icon_(std::move(icon)), tooltip_(std::move(tooltip)) {}

    std::string Name() const override { return object_.ObjectName(); }
    BarGroup    Group() const override { return group_; }
    BarIcon     Icon() const override { return ResourceIcon{icon_}; }
    std::string Tooltip() const override { return tooltip_; }

    uint64_t RxCount() const override { return object_.RxCount(); }
    uint64_t TxCount() const override { return object_.TxCount(); }

private:
    cerfcore::MachineObject& object_;
    BarGroup                 group_;
    std::string              icon_;
    std::string              tooltip_;
};

class ActivityBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        switch (object.ObjectKind()) {
            case cerfcore::MachineObjectKind::kAudio:
                return std::make_unique<ActivityBarWidget>(object, BarGroup::Indicator, "speaker",
                                                           "Audio - TX: sound output, RX: microphone");
            case cerfcore::MachineObjectKind::kUsbFlasher:
                return std::make_unique<ActivityBarWidget>(object, BarGroup::Usb, "usb_ford_flasher",
                                                           "USB - " + object.ObjectName());
            default:
                return nullptr;
        }
    }
};

}

REGISTER_SERVICE(ActivityBarWidgetSource);

}
