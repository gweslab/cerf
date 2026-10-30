#pragma once

#include "hud_layout.h"
#include "view_presentation.h"

#include <cerfcore/core/service.h>

#include <string>

namespace cerfcore {
struct DbHud;
}

namespace cerffrontend {

class HudSelection : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

    const cerfcore::DbHud* Active() const { return active_; }
    bool                   Shown() const { return active_ != nullptr; }
    bool                   CanShow() const;
    void                   SetShown(bool shown);
    void                   Toggle();
    ContentFrame           Frame() const;
    HudInsets              InsideInsets(double area_w, double area_h, int quarter, double fb_w, double fb_h) const;

private:
    const cerfcore::DbHud* Resolve(const std::string& setting) const;
    void                   Apply();

    const cerfcore::DbHud* active_ = nullptr;
    std::string            restore_setting_;
};

}
