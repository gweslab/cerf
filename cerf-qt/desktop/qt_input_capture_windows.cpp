#define NOMINMAX

#include "../input_capture.h"
#include "low_level_keyboard_hook.h"

#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_gate.h>

#include <windows.h>

namespace {

class QtInputCapture : public cerffrontend::InputCapture {
public:
    using cerffrontend::InputCapture::InputCapture;

    void OnReady() override {
        auto& window = emu_.Get<QtMainWindow>();
        window.RunOnUiThread([this, &window] {
            hook_.Install([this, &window](uint32_t vk, bool key_up) {
                if (!IsCaptured()) return false;
                if (GetForegroundWindow() != reinterpret_cast<HWND>(window.NativeHandle()))
                    return false;
                bool eaten = false;
                gate_.Run([&](cerfcore::CerfEmulator&) { eaten = OnHostKey(vk, key_up); });
                return eaten;
            });
        });
    }

    void OnShutdown() override { hook_.Remove(); }

private:
    const cerfcore::InstanceGate       gate_{emu_};
    cerffrontend::LowLevelKeyboardHook hook_;
};

}

REGISTER_SERVICE_AS(QtInputCapture, cerffrontend::InputCapture);
