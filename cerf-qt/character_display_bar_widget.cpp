#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_indicators.h>
#include <cerfcore/host/machine_object_tree.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

class CharacterDisplayBarWidget final : public BarWidget {
public:
    CharacterDisplayBarWidget(cerfcore::CerfEmulator& emu, cerfcore::MachineCharacterDisplay& display)
        : emu_(emu), display_(display) {}

    std::string Name() const override { return display_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Indicator; }

    BarIcon Icon() const override {
        LedGridIcon icon;
        for (cerfcore::MachineObject* child : emu_.Get<cerfcore::MachineObjectTree>().Children(&display_)) {
            auto* lamp = dynamic_cast<cerfcore::MachineLamp*>(child);
            if (!lamp) continue;
            const cerfcore::LampState state = lamp->Lamp();
            icon.cells.push_back(LedGridCell{state.lit, Rgb{state.color.r, state.color.g, state.color.b}});
        }
        return icon;
    }

    std::string Tooltip() const override { return Name() + "  '" + display_.Characters() + "'"; }

private:

    cerfcore::CerfEmulator&            emu_;
    cerfcore::MachineCharacterDisplay& display_;
};

class CharacterDisplayBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* display = dynamic_cast<cerfcore::MachineCharacterDisplay*>(&object);
        if (!display) return nullptr;
        return std::make_unique<CharacterDisplayBarWidget>(emu_, *display);
    }
};

}

REGISTER_SERVICE(CharacterDisplayBarWidgetSource);

}
