#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_indicators.h>
#include <cerfcore/host/machine_object_tree.h>

#include <memory>
#include <string>
#include <vector>

namespace cerffrontend {

namespace {

Rgb FromObject(cerfcore::ObjectRgb c) { return Rgb{c.r, c.g, c.b}; }

LampLook LookOf(const cerfcore::LampState& state) {
    LampLook look;
    look.lit      = state.lit;
    look.color    = FromObject(state.color);
    look.blinking = state.blinking;
    look.on_ms    = state.blink_on_ms;
    look.off_ms   = state.blink_off_ms;
    if (state.between_blinks) look.between = FromObject(*state.between_blinks);
    return look;
}

class LampBarWidget final : public BarWidget {
public:
    LampBarWidget(cerfcore::CerfEmulator& emu, cerfcore::MachineLamp& lamp) : emu_(emu), lamp_(lamp) {}

    std::string Name() const override { return lamp_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Indicator; }

    BarIcon Icon() const override {
        const Parts parts = Gather();
        LedIcon     icon;
        icon.lamps.push_back(LookOf(lamp_.Lamp()));
        for (const cerfcore::MachineLamp* element : parts.lamps) icon.lamps.push_back(LookOf(element->Lamp()));
        icon.vibrate = parts.vibrator && parts.vibrator->Vibrating();
        return icon;
    }

    std::string Tooltip() const override {
        const Parts               parts = Gather();
        const cerfcore::LampState state = lamp_.Lamp();
        std::string               text  = Name() + " - " + (state.blinking ? "blinking" : state.lit ? "on" : "off");
        if (parts.vibrator) text += std::string(" · Vibrate: ") + (parts.vibrator->Vibrating() ? "on" : "off");
        for (const cerfcore::MachineLamp* element : parts.lamps)
            text += "\n" + element->ObjectName() + (element->Lamp().lit ? ": on" : ": off");
        if (parts.button) text += " (click = press the " + parts.button->ObjectName() + ")";
        return text;
    }

    bool PrimaryClick() override {
        cerfcore::MachineButton* button = Gather().button;
        if (!button) return false;
        button->Press();
        return true;
    }

    std::vector<MenuItem> Menu() override {
        cerfcore::MachineButton* button = Gather().button;
        if (!button) return {};
        return {MenuItem::Action("Press the " + button->ObjectName(), [button] { button->Press(); })};
    }

private:
    struct Parts {
        std::vector<cerfcore::MachineLamp*> lamps;
        cerfcore::MachineVibrator*          vibrator = nullptr;
        cerfcore::MachineButton*            button   = nullptr;
    };

    Parts Gather() const {
        Parts parts;
        for (cerfcore::MachineObject* child : emu_.Get<cerfcore::MachineObjectTree>().Children(&lamp_)) {
            if (auto* l = dynamic_cast<cerfcore::MachineLamp*>(child)) parts.lamps.push_back(l);
            if (auto* v = dynamic_cast<cerfcore::MachineVibrator*>(child)) parts.vibrator = v;
            if (auto* b = dynamic_cast<cerfcore::MachineButton*>(child)) parts.button = b;
        }
        return parts;
    }

    cerfcore::CerfEmulator& emu_;
    cerfcore::MachineLamp&  lamp_;
};

class LampBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* lamp = dynamic_cast<cerfcore::MachineLamp*>(&object);
        if (!lamp) return nullptr;
        return std::make_unique<LampBarWidget>(emu_, *lamp);
    }
};

}

REGISTER_SERVICE(LampBarWidgetSource);

}
