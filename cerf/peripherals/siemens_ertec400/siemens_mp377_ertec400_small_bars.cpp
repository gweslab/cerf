#include "siemens_mp377_ertec400_bar_window.h"
#include "siemens_mp377_ertec400.h"
#include "siemens_mp377_ertec400_model.h"
#include "siemens_mp377_ertec400_nrt.h"

#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"

namespace {
class SiemensMp377Ertec400SmallBars final : public SiemensMp377Ertec400BarWindow {
public:
    using SiemensMp377Ertec400BarWindow::SiemensMp377Ertec400BarWindow;
    uint32_t MmioBase() const override { return siemens_mp377::kErtecSmallWindowBase; }
    uint32_t MmioSize() const override { return siemens_mp377::kErtecSmallWindowSize; }

    void SaveState(StateWriter& writer) override {
        emu_.Get<SiemensMp377Ertec400Model>().SaveState(writer);
        emu_.Get<SiemensMp377Ertec400Nrt>().SaveState(writer);
    }
    void RestoreState(StateReader& reader) override {
        emu_.Get<SiemensMp377Ertec400Model>().RestoreState(reader);
        emu_.Get<SiemensMp377Ertec400Nrt>().RestoreState(reader);
    }
    void PostRestore() override { emu_.Get<SiemensMp377Ertec400Nrt>().PostRestore(); }

};
} // namespace
REGISTER_SERVICE(SiemensMp377Ertec400SmallBars);
