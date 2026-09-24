#include "../mips_kseg_dram_rom_page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "nec_mobilepro_790_id.h"

#include <cstdint>

namespace {

/* DRAM space PA 0x00000000-0x07FFFFFF (VR4121 UM Table 6-6). */
constexpr uint32_t kDramVaBase = 0x80000000u;
constexpr uint32_t kDramPaBase = 0x00000000u;
constexpr uint32_t kDramSize   = 0x02000000u;

class NecMobilePro790PageTableBuilder : public MipsKsegDramRomPageTableBuilder {
public:
    explicit NecMobilePro790PageTableBuilder(CerfEmulator& emu)
        : MipsKsegDramRomPageTableBuilder(emu, {
              { kDramVaBase, kDramPaBase, kDramSize }, 0u, kDramSize,
          }) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro790;
    }
};

}

REGISTER_SERVICE_AS(NecMobilePro790PageTableBuilder, PageTableBuilder);
