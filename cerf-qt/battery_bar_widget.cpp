#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/battery.h>

#include <cstdio>
#include <memory>
#include <string>

namespace cerffrontend {

namespace {

constexpr int kLevelHigh = 65;
constexpr int kLevelLow  = 20;

BatteryLevel LevelOf(int charge) {
    if (charge >= kLevelHigh) return BatteryLevel::kHigh;
    return charge >= kLevelLow ? BatteryLevel::kLow : BatteryLevel::kCritical;
}

class BatteryBarWidget final : public BarWidget {
public:
    explicit BatteryBarWidget(cerfcore::Battery& battery) : battery_(battery) {}

    std::string Name() const override { return battery_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Power; }

    BarIcon Icon() const override {
        const int charge = battery_.ChargePercent();
        return BatteryIcon{charge, battery_.OnBattery(), LevelOf(charge)};
    }

    std::string Tooltip() const override {
        const int          charge = battery_.ChargePercent();
        const BatteryLevel level  = LevelOf(charge);
        const char*        word   = level == BatteryLevel::kHigh  ? "High"
                                    : level == BatteryLevel::kLow ? "Low"
                                                                  : "Critical";
        char text[96];
        std::snprintf(text, sizeof(text), "Battery - %s, %d%% (%s)", battery_.OnBattery() ? "on battery" : "on AC",
                      charge, word);
        return text;
    }

    std::vector<MenuItem> Menu() override {
        const bool            on_battery = battery_.OnBattery();
        const int             charge     = battery_.ChargePercent();
        std::vector<MenuItem> levels;
        for (int preset : {100, 80, 60, 40, 20, 5})
            levels.push_back(MenuItem::Radio(std::to_string(preset) + "%", charge == preset,
                                             [this, preset] { battery_.SetChargePercent(preset); }));
        return {
            MenuItem::Check("On battery power", on_battery,
                            [this, on_battery] { battery_.SetOnBattery(!on_battery); }),
            MenuItem{},
            MenuItem::Submenu("Charge level", std::move(levels)),
        };
    }

private:
    cerfcore::Battery& battery_;
};

class BatteryBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* battery = dynamic_cast<cerfcore::Battery*>(&object);
        if (!battery) return nullptr;
        return std::make_unique<BatteryBarWidget>(*battery);
    }
};

}

REGISTER_SERVICE(BatteryBarWidgetSource);

}
