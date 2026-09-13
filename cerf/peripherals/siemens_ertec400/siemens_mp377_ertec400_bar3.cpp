#include "siemens_mp377_ertec400_bar_window.h"
#include "siemens_mp377_ertec400.h"

#include "../../core/cerf_emulator.h"

namespace {
class SiemensMp377Ertec400Bar3 final : public SiemensMp377Ertec400BarWindow {
public:
    using SiemensMp377Ertec400BarWindow::SiemensMp377Ertec400BarWindow;
    uint32_t MmioBase() const override { return siemens_mp377::kErtecBar3WindowBase; }
    uint32_t MmioSize() const override { return siemens_mp377::kErtecBar3WindowSize; }

};
} // namespace
REGISTER_SERVICE(SiemensMp377Ertec400Bar3);
