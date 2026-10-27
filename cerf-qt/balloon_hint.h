#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <string>

namespace cerfcore { class HostWidget; }

namespace cerffrontend {

class BalloonHint : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr int kCanvasBottomGap = 20;

    virtual void ShowUnderWidget(const cerfcore::HostWidget* anchor, const std::string& text,
                                 uint32_t hold_ms)                                   = 0;
    virtual void ShowUnderCaptureWidget(const std::string& text, uint32_t hold_ms) = 0;
};

}
