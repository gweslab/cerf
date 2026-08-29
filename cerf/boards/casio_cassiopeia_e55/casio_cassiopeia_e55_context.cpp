#include "../board_context.h"

#include "../../core/cerf_emulator.h"

namespace {

class CasioCassiopeiaE55Context : public BoardContext {
public:
    using BoardContext::BoardContext;

    Board          GetBoard()           const override { return Board::CasioCassiopeiaE55; }
    SocFamily      GetSoc()             const override { return SocFamily::VR4111; }
    CpuArch        GetCpuArch()         const override { return CpuArch::Mips; }
    RomPlacingMode GetRomPlacingMode()  const override { return RomPlacingMode::FlatContainer; }

    uint32_t GetGuestAdditionsColorDepth() const override { return 8u; }

    /* VR4111 UM Table 6-6 p166 types 0x0D000000 to 0x0FFFFFFF as space reserved for
       future use, 48 M. */
    uint32_t GuestAdditionsWindowBase() const override { return 0x0D000000u; }

    std::optional<PreferredWindowSize> GetPreferredWindowSize() const override {
        return PreferredWindowSize{ 240, 320 };
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioCassiopeiaE55Context, BoardContext);
