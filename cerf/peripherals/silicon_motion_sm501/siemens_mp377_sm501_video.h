#pragma once

#include "../../core/service.h"
#include "../../lcd/display_mode_latch.h"

#include <cstdint>

class StateReader;
class StateWriter;

namespace siemens_mp377 {

class SiemensMp377Sm501Video : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    const uint8_t* Vram();
    bool WasWritten();

    bool WriteVramByte(uint32_t offset, uint8_t value);
    bool WriteVramHalf(uint32_t offset, uint16_t value);
    bool WriteVramWord(uint32_t offset, uint32_t value);

    uint32_t PanelFbOffset();
    uint32_t PanelPitchBytes();
    uint32_t PanelWidth();
    uint32_t PanelHeight();
    bool UsesCrt();
    uint32_t DisplayFbOffset();
    uint32_t DisplayPitchBytes();
    uint32_t DisplayWidth();
    uint32_t DisplayHeight();
    uint32_t DisplayControl();
    uint32_t DisplayPaletteEntry(uint8_t index);
    uint32_t DisplayCursorAddress();
    uint32_t DisplayCursorLocation();
    uint32_t DisplayCursorColors12();
    uint32_t DisplayCursorColor3();

    void PublishDisplayMode();
    void ResetDisplayMode();
    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

private:
    DisplayModeLatch mode_latch_;
};

} // namespace siemens_mp377
