#include "../board_context.h"

#include "siemens_mp377_panel.h"

#include "../../core/cerf_emulator.h"

namespace {

class SiemensMp377Context : public BoardContext {
public:
    using BoardContext::BoardContext;

    Board GetBoard() const override { return Board::SiemensMP377; }
    SocFamily GetSoc() const override { return SocFamily::IOP13xx; }
    CpuArch GetCpuArch() const override { return CpuArch::Arm; }
    RomPlacingMode GetRomPlacingMode() const override { return RomPlacingMode::FlatContainer; }

    std::optional<PreferredWindowSize> GetPreferredWindowSize() const override {
        return PreferredWindowSize{siemens_mp377::kMp377HwiPanel.width, siemens_mp377::kMp377HwiPanel.height};
    }
};

} /* namespace */

REGISTER_SERVICE_AS(SiemensMp377Context, BoardContext);
