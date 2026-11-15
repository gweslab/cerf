#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_object_tree.h>
#include <cerfcore/host/machine_temperature_sensor.h>

#include <cstdint>
#include <cstdio>
#include <iterator>
#include <memory>
#include <optional>
#include <string>

namespace cerffrontend {

namespace {

constexpr int16_t kCelsius[]    = {-40, -30, -20, -10, -5, 0, 5, 10, 15, 20, 25, 30, 35, 40, 50};
constexpr int16_t kFahrenheit[] = {-40, -22, -4, 14, 23, 32, 41, 50, 59, 68, 77, 86, 95, 104, 122};

class CarBarWidget final : public BarWidget {
public:
    CarBarWidget(cerfcore::CerfEmulator& emu, cerfcore::MachineObject& car) : emu_(emu), car_(car) {}

    std::string Name() const override { return car_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Indicator; }
    BarIcon     Icon() const override { return ResourceIcon{"car"}; }

    std::string Tooltip() const override {
        cerfcore::MachineTemperatureSensor* sensor = Sensor();
        return "SYNC 2 car controls" + (sensor ? "\n" + Label(*sensor) : std::string());
    }

    std::vector<MenuItem> Menu() override {
        cerfcore::MachineTemperatureSensor* sensor = Sensor();
        if (!sensor) return {};
        const cerfcore::TemperatureReading reading = sensor->Reading();
        std::vector<MenuItem>              items;
        for (std::size_t i = 0; i < std::size(kCelsius); ++i) {
            const int16_t half  = static_cast<int16_t>(kCelsius[i] * 2);
            const int     shown = imperial_ ? kFahrenheit[i] : kCelsius[i];
            items.push_back(MenuItem::Radio(std::to_string(shown) + (imperial_ ? " °F" : " °C"),
                                            reading.reported && reading.half_celsius == half,
                                            [sensor, half] { sensor->SetReading({true, half}); }));
        }
        items.push_back(MenuItem::Radio("No reading", reading.reported && !reading.half_celsius,
                                        [sensor] { sensor->SetReading({true, std::nullopt}); }));
        items.push_back(MenuItem::Radio("Stop reporting outside temperature", !reading.reported,
                                        [sensor] { sensor->SetReading({false, std::nullopt}); }));
        items.push_back(MenuItem::Check("Show presets in °F", imperial_, [this] { imperial_ = !imperial_; }));
        return {MenuItem::Submenu(Label(*sensor), std::move(items))};
    }

private:
    cerfcore::MachineTemperatureSensor* Sensor() const {
        for (cerfcore::MachineObject* child : emu_.Get<cerfcore::MachineObjectTree>().Children(&car_))
            if (auto* sensor = dynamic_cast<cerfcore::MachineTemperatureSensor*>(child)) return sensor;
        return nullptr;
    }

    std::string Label(const cerfcore::MachineTemperatureSensor& sensor) const {
        const cerfcore::TemperatureReading reading = sensor.Reading();
        if (!reading.reported) return sensor.ObjectName() + ": Not reported";
        if (!reading.half_celsius) return sensor.ObjectName() + ": No reading";
        char text[64];
        if (imperial_)
            std::snprintf(text, sizeof(text), ": %.1f °F", *reading.half_celsius * 0.9 + 32.0);
        else
            std::snprintf(text, sizeof(text), ": %.1f °C", *reading.half_celsius * 0.5);
        return sensor.ObjectName() + text;
    }

    cerfcore::CerfEmulator&  emu_;
    cerfcore::MachineObject& car_;
    bool                     imperial_ = false;
};

class CarBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        if (object.ObjectKind() != cerfcore::MachineObjectKind::kCar) return nullptr;
        return std::make_unique<CarBarWidget>(emu_, object);
    }
};

}

REGISTER_SERVICE(CarBarWidgetSource);

}
