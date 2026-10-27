#include <cerfcore/host/pointer_host_options.h>

#include "CerfStyle/touch_frontend.h"
#include "pointer_stylus_simulation.h"
#include "stylus_alt_tap.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/pointer_input.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>
#include <cerfcore/state/state_stream.h>

#include <vector>

namespace cerffrontend {

namespace {

class FrontendPointerHostOptions : public cerfcore::PointerHostOptions {
public:
    using cerfcore::PointerHostOptions::PointerHostOptions;

    bool Supported() const override { return emu_.Get<StylusAltTap>().Supported(); }

    std::vector<cerfcore::WidgetControl> Controls() override {
        std::vector<cerfcore::WidgetControl> controls;
        if (AltTapItemVisible()) {
            cerfcore::ToggleControl t;
            t.id    = "alt_tap";
            t.label = "Do Alt+Tap when you Right Click";
            t.value = emu_.Get<StylusAltTap>().Enabled();
            t.set   = [this](bool on) { emu_.Get<StylusAltTap>().SetEnabled(on); };
            controls.push_back(cerfcore::WidgetControl{std::move(t)});
        }
        if (StylusSimItemVisible()) {
            cerfcore::ToggleControl t;
            t.id    = "stylus_simulation";
            t.label = "Send movement only when mouse is clicked (stylus simulation)";
            t.value = emu_.Get<PointerStylusSimulation>().Enabled();
            t.set   = [this](bool on) { emu_.Get<PointerStylusSimulation>().SetEnabled(on); };
            controls.push_back(cerfcore::WidgetControl{std::move(t)});
        }
        return controls;
    }

    void SaveState(cerfcore::StateWriter& w) const override {
        w.Write<uint8_t>("alt_tap_enabled", emu_.Get<StylusAltTap>().Enabled() ? 1u : 0u);
        w.Write<uint8_t>("stylus_sim_enabled",
                         emu_.Get<PointerStylusSimulation>().Enabled() ? 1u : 0u);
        emu_.Get<StylusAltTap>().SaveState(w);
    }

    void RestoreState(cerfcore::StateReader& r) override {
        uint8_t alt_tap = 1;
        r.Read("alt_tap_enabled", alt_tap);
        auto& tap = emu_.Get<StylusAltTap>();
        tap.SetEnabled(alt_tap != 0);
        uint8_t stylus_sim = 0;
        r.Read("stylus_sim_enabled", stylus_sim);
        emu_.Get<PointerStylusSimulation>().SetEnabled(stylus_sim != 0);
        tap.RestoreState(r);
    }

private:
    bool AltTapItemVisible() const {
        cerfcore::PointerSource* active = emu_.Get<cerfcore::PointerRouter>().Active();
        return active && active->Kind() == cerfcore::PointerKind::Stylus &&
               emu_.Get<StylusAltTap>().Armable();
    }

    bool StylusSimItemVisible() const {
        if (TouchFrontend::Active()) return false;
        auto* ga = emu_.TryGet<cerfcore::PointerInput>();
        return ga && emu_.Get<cerfcore::PointerRouter>().Active() ==
                         static_cast<cerfcore::PointerSource*>(ga);
    }
};

}

REGISTER_SERVICE_AS(FrontendPointerHostOptions, cerfcore::PointerHostOptions);

}
