#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_phone_line.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

class PhoneLineBarWidget final : public BarWidget {
public:
    explicit PhoneLineBarWidget(cerfcore::MachinePhoneLine& line) : line_(line) {}

    std::string Name() const override { return line_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Network; }
    BarIcon     Icon() const override { return ResourceIcon{line_.Plugged() ? "serial_modem" : "modem_disabled"}; }

    std::string Tooltip() const override {
        return Name() + (line_.Plugged() ? " - phone line plugged in" : " - phone line unplugged");
    }

    bool PrimaryClick() override {
        line_.SetPlugged(!line_.Plugged());
        return true;
    }

    std::vector<MenuItem> Menu() override {
        const bool plugged = line_.Plugged();
        return {MenuItem::Action(plugged ? "Unplug the phone line" : "Plug in the phone line",
                                 [this, plugged] { line_.SetPlugged(!plugged); })};
    }
    bool MenuIsOneAction() const override { return true; }

    uint64_t RxCount() const override { return line_.RxCount(); }
    uint64_t TxCount() const override { return line_.TxCount(); }

private:
    cerfcore::MachinePhoneLine& line_;
};

class PhoneLineBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* line = dynamic_cast<cerfcore::MachinePhoneLine*>(&object);
        if (!line) return nullptr;
        return std::make_unique<PhoneLineBarWidget>(*line);
    }
};

}

REGISTER_SERVICE(PhoneLineBarWidgetSource);

}
