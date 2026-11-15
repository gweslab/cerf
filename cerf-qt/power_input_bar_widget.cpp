#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_power_input.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

class PowerInputBarWidget final : public BarWidget {
public:
    explicit PowerInputBarWidget(cerfcore::MachinePowerInput& input) : input_(input) {}

    std::string Name() const override { return input_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Power; }
    BarIcon     Icon() const override { return PowerInputIcon{input_.PowerFailed()}; }

    std::string Tooltip() const override {
        return Name() + (input_.PowerFailed() ? " - failure asserted" : " - available");
    }

    std::vector<MenuItem> Menu() override {
        const bool failed = input_.PowerFailed();
        return {MenuItem::Check("Assert power-fail input", failed, [this, failed] { input_.SetPowerFailed(!failed); })};
    }

private:
    cerfcore::MachinePowerInput& input_;
};

class PowerInputBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* input = dynamic_cast<cerfcore::MachinePowerInput*>(&object);
        if (!input) return nullptr;
        return std::make_unique<PowerInputBarWidget>(*input);
    }
};

}

REGISTER_SERVICE(PowerInputBarWidgetSource);

}
