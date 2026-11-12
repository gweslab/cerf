#pragma once

#include "external_display_container.h"
#include "widget_menu_model.h"

#include <cerfcore/core/service.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class EmulatorWindowHost : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual void ShowWindow()                            = 0;
    virtual void PlaceWindow()                           = 0;
    virtual void Raise()                                 = 0;
    virtual bool IsFullscreen() const                    = 0;
    virtual void ToggleFullscreen()                      = 0;
    virtual void MatchGuestSize()                        = 0;
    virtual void RefitIfFollowingGuest()                 = 0;
    virtual void FitToResolution(uint32_t w, uint32_t h) = 0;
    virtual void RefitForPresentation()                  = 0;
    virtual void OnTeardownWedged()                      = 0;

    virtual std::vector<std::string>            MenuTitles()    = 0;
    virtual std::vector<cerffrontend::MenuItem> Menu(int index) = 0;

    virtual std::unique_ptr<ExternalDisplayContainer> OpenExternalDisplay(int source_id, const std::string& title,
                                                                          uint32_t w, uint32_t h) = 0;
};
