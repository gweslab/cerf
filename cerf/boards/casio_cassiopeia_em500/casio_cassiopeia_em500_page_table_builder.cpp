#include "../mips_kseg_dram_rom_page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "casio_cassiopeia_em500_id.h"

#include <cstdint>

namespace {

/* DRAM area PA 0x00000000-0x07FFFFFF (VR4131 UM Fig 3-1); ROMHDR
   ulRAMStart 0x80051000 / ulRAMEnd 0x81000000 place this board's populated
   DRAM at kseg0 0x80000000, 16 MB. */
constexpr uint32_t kDramVaBase = 0x80000000u;
constexpr uint32_t kDramPaBase = 0x00000000u;
constexpr uint32_t kDramSize   = 0x01000000u;

class CasioCassiopeiaEm500PageTableBuilder : public MipsKsegDramRomPageTableBuilder {
public:
    explicit CasioCassiopeiaEm500PageTableBuilder(CerfEmulator& emu)
        : MipsKsegDramRomPageTableBuilder(emu, {
              { kDramVaBase, kDramPaBase, kDramSize }, 0u, kDramSize,
          }) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::CasioCassiopeiaEm500;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioCassiopeiaEm500PageTableBuilder, PageTableBuilder);
