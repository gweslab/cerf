#include "../input_capture.h"

#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>

namespace {

class QtInputCapture : public cerffrontend::InputCapture {
public:
    using cerffrontend::InputCapture::InputCapture;

protected:
    void OnCaptureChanged(bool on) override { emu_.Get<QtMainWindow>().SetKeyboardGrab(on); }
};

}

REGISTER_SERVICE_AS(QtInputCapture, cerffrontend::InputCapture);
