#pragma once

#include "viewport_menu.h"
#include "../widget_menu_model.h"

#include <cerfcore/core/service.h>

#include <string>
#include <vector>

namespace cerffrontend {

class HostMenuModel : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int kMenuCount = 3;

    const char*           Title(int index) const;
    std::vector<MenuItem> Build(int index);

private:
    class MainViewport final : public ViewportMenuTarget {
    public:
        explicit MainViewport(cerfcore::CerfEmulator& emu) : emu_(emu) {}

        ViewportMode Mode() const override;
        int          IntegerFactor() const override;
        bool         Antialias() const override;
        void         SetViewportMode(ViewportMode m) override;
        void         SetIntegerScale(int factor) override;
        void         SetAntialias(bool on) override;
        bool         IsFullscreen() const override;
        void         ToggleFullscreen() override;
        void         SaveScreenshot() override;
        void         CopyScreenshot() override;
        void         AfterModeChange(bool integer_scale) override;

    private:
        cerfcore::CerfEmulator& emu_;
    };

    std::vector<MenuItem> Actions();
    std::vector<MenuItem> View();
    std::vector<MenuItem> Help();
    void                  PickStateFile(bool save);
    void                  ConfirmHardReset();
    std::string           EmulatedDeviceLine() const;

    MainViewport main_viewport_{emu_};
};

}
