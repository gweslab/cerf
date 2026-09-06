#include "../board_context.h"

#include "../../core/cerf_emulator.h"

namespace {

class SymbolMk500Context : public BoardContext {
public:
    using BoardContext::BoardContext;

    Board       GetBoard()  const override { return Board::SymbolMk500; }
    SocFamily   GetSoc()    const override { return SocFamily::PXA27x; }
    CpuArch     GetCpuArch() const override { return CpuArch::Arm; }
    RomPlacingMode GetRomPlacingMode() const override { return RomPlacingMode::FlatContainer; }

    std::optional<PreferredWindowSize> GetPreferredWindowSize() const override {
        return PreferredWindowSize{ 320, 240 };
    }
};

}

REGISTER_SERVICE_AS(SymbolMk500Context, BoardContext);
