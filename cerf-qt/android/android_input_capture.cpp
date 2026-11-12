#include "../input_capture.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class AndroidInputCapture : public cerffrontend::InputCapture {
public:
    using cerffrontend::InputCapture::InputCapture;
};

}

REGISTER_SERVICE_AS(AndroidInputCapture, cerffrontend::InputCapture);
