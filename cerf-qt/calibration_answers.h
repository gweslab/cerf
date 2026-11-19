#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <functional>

namespace cerffrontend {

enum class CalibrationQuestion : uint8_t { kCalibrate, kPanelResolution };

class CalibrationAnswers : public cerfcore::Service {
public:
    using cerfcore::Service::Service;
    using Answer = std::function<void(bool yes)>;

    virtual void Opened(CalibrationQuestion question, uint32_t width, uint32_t height, Answer answer) = 0;
    virtual void Closed()                                                                         = 0;
};

}
