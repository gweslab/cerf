#include "../input_capture.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class MobileInputCapture : public cerffrontend::InputCapture {
public:
    using cerffrontend::InputCapture::InputCapture;
};

}

REGISTER_SERVICE_AS(MobileInputCapture, cerffrontend::InputCapture);
