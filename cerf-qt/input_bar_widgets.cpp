#include "CerfStyle/touch_frontend.h"
#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/keyboard_input.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/machine_object_tree.h>
#include <cerfcore/host/machine_pointer_feature.h>
#include <cerfcore/host/pointer_input.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

const char* PointerIcon(const cerfcore::PointerSource* source) {
    if (!source) return "ga_cursor";
    switch (source->Kind()) {
        case cerfcore::PointerKind::Stylus:   return "stylus";
        case cerfcore::PointerKind::Relative: return "cursor";
        case cerfcore::PointerKind::Absolute: return "ga_cursor";
    }
    return "ga_cursor";
}

class KeyboardBarWidget final : public BarWidget {
public:
    explicit KeyboardBarWidget(cerfcore::CerfEmulator& emu) : emu_(emu) {}

    std::string Name() const override { return Router().ObjectName(); }
    BarGroup    Group() const override { return BarGroup::InputControl; }
    bool        Shown() const override { return Router().Sources().size() > 1; }

    BarIcon Icon() const override {
        const cerfcore::KeyboardInput* active = Router().Active();
        return ResourceIcon{active && !active->Stock() ? "ga_keyboard" : "keyboard"};
    }

    std::string Tooltip() const override {
        const cerfcore::KeyboardInput* active = Router().Active();
        return (active ? active->SourceName() : Name()) + " - click to configure input";
    }

    std::vector<MenuItem> Menu() override {
        std::vector<MenuItem>    items;
        cerfcore::KeyboardInput* active = Router().Active();
        for (cerfcore::KeyboardInput* source : Router().Sources())
            items.push_back(MenuItem::Radio(source->SourceName(), source == active,
                                            [this, source] { Router().SetActive(source); }));
        return items;
    }

private:
    cerfcore::KeyboardRouter& Router() const { return emu_.Get<cerfcore::KeyboardRouter>(); }

    cerfcore::CerfEmulator&        emu_;
};

class PointerBarWidget final : public BarWidget {
public:
    explicit PointerBarWidget(cerfcore::CerfEmulator& emu) : emu_(emu) {}

    std::string Name() const override { return Router().ObjectName(); }
    BarGroup    Group() const override { return BarGroup::InputControl; }
    bool        Shown() const override { return Router().Sources().size() > 1 || !Features().empty(); }
    BarIcon     Icon() const override { return ResourceIcon{PointerIcon(Router().Active())}; }

    std::string Tooltip() const override {
        const cerfcore::PointerSource* active = Router().Active();
        std::string                    tip    = active ? active->SourceName() : Name();
        if (Router().Sources().size() > 1) return tip + " - click to switch input device";
        if (!Features().empty()) return tip + " - click to configure";
        return tip;
    }

    bool PrimaryClick() override {
        if (Router().Sources().size() < 2) return false;
        Router().CycleNext();
        return true;
    }

    std::vector<MenuItem> Menu() override {
        std::vector<MenuItem>    items;
        cerfcore::PointerSource* active  = Router().Active();
        const auto               sources = Router().Sources();
        if (sources.size() > 1)
            for (cerfcore::PointerSource* source : sources)
                items.push_back(MenuItem::Radio(source->SourceName(), source == active,
                                                [this, source] { Router().SetActive(source); }));
        const auto features = Features();
        if (!features.empty() && !items.empty()) items.push_back(MenuItem{});
        for (cerfcore::MachinePointerFeature* feature : features)
            items.push_back(MenuItem::Check(FeatureLabel(*feature), feature->Enabled(),
                                            [feature, on = !feature->Enabled()] { feature->SetEnabled(on); }));
        return items;
    }

private:
    cerfcore::PointerRouter& Router() const { return emu_.Get<cerfcore::PointerRouter>(); }

    static std::string FeatureLabel(const cerfcore::MachinePointerFeature& feature) {
        if (feature.ObjectId() == "alt_tap") return "Do Alt+Tap when you Right Click";
        if (feature.ObjectId() == "stylus_simulation")
            return "Send movement only when mouse is clicked (stylus simulation)";
        return feature.ObjectName();
    }

    std::vector<cerfcore::MachinePointerFeature*> Features() const {
        std::vector<cerfcore::MachinePointerFeature*> out;
        for (cerfcore::MachineObject* child : emu_.Get<cerfcore::MachineObjectTree>().Children(&Router())) {
            auto* feature = dynamic_cast<cerfcore::MachinePointerFeature*>(child);
            if (!feature || !feature->Available()) continue;
            if (feature->ObjectId() == "stylus_simulation" && TouchFrontend::Active()) continue;
            out.push_back(feature);
        }
        return out;
    }

    cerfcore::CerfEmulator&        emu_;
};

class InputBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        if (dynamic_cast<cerfcore::KeyboardRouter*>(&object)) return std::make_unique<KeyboardBarWidget>(emu_);
        if (dynamic_cast<cerfcore::PointerRouter*>(&object)) return std::make_unique<PointerBarWidget>(emu_);
        return nullptr;
    }
};

}

REGISTER_SERVICE(InputBarWidgetSource);

}
