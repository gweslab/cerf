#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../boards/page_table_builder.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "pr31500_id.h"
#include "pr31700_id.h"

#include <cstdint>
#include <string_view>

namespace {

/* TMPR3911 §4.2.1 p4-3: CS0, the boot ROM chip select, "is mapped starting at address $11000000".
   philips_nino_300 nk.exe 0x9F4115CC, philips_velo_1_ce1 nk.exe 0x9F40E934 and philips_velo_1_ce2
   nk.exe 0x9000F6EC read words over 0xB1000000-0xB10003FC into $t2 and never read $t2. */
constexpr uint32_t kWindowBase = 0x11000000u;
constexpr uint32_t kWindowSize = 0x400u;

class Pr31x00Cs0Unbacked : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        if (soc != SocId::Pr31500 && soc != SocId::Pr31700) return false;
        for (const BackedRegion& r : emu_.Get<PageTableBuilder>().BackedMemoryRegions()) {
            if (kWindowBase - r.pa_base < r.size) return false;
        }
        return true;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kWindowBase; }
    uint32_t MmioSize() const override { return kWindowSize; }

    uint32_t ReadWord(uint32_t) override { return 0u; }
};

}

REGISTER_SERVICE(Pr31x00Cs0Unbacked);
