#include "../mips_kseg_dram_rom_page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "casio_cassiopeia_e55_id.h"

#include <cstdint>

namespace {

/* DRAM space PA 0x00000000-0x03FFFFFF (VR4111 UM Table 6-6). The E-55 ships 16 MB
   of it: "NEC VR4111 69MHz", "16MB" (PC Watch,
   https://pc.watch.impress.co.jp/docs/article/981203/casio.htm). */
constexpr uint32_t kDramVaBase   = 0x80000000u;
constexpr uint32_t kDramPaBase   = 0x00000000u;
constexpr uint32_t kDramSize     = 0x01000000u;
constexpr uint32_t kDramSpanSize = 0x04000000u;

/* ROM space PA 0x18000000-0x1FFFFFFF (VR4111 UM Table 6-6). The dump's second
   XIP (ROMHDR physfirst 0x9FC00000, nummods 1) sits at the MIPS reset vector
   PA 0x1FC00000. */
constexpr uint32_t kRomVaBase  = 0x9E800000u;
constexpr uint32_t kRomPaBase  = 0x1E800000u;
constexpr uint32_t kRomSize    = 0x01800000u;

class CasioCassiopeiaE55PageTableBuilder : public MipsKsegDramRomPageTableBuilder {
public:
    explicit CasioCassiopeiaE55PageTableBuilder(CerfEmulator& emu)
        : MipsKsegDramRomPageTableBuilder(emu, {
              { kDramVaBase, kDramPaBase, kDramSize }, 0u, kDramSpanSize,
          }, { kRomVaBase, kRomPaBase, kRomSize }) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::CasioCassiopeiaE55;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioCassiopeiaE55PageTableBuilder, PageTableBuilder);
