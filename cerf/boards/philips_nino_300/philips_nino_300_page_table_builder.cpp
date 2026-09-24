#include "../mips_kseg_dram_rom_page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "philips_nino_300_id.h"

#include <cstdint>

namespace {

constexpr uint32_t kDramVaBase = 0x80000000u;

/* MEM_CONFIG0 = (old & 1) | 0x20800A on cold start (nk.exe sub_9F411754), so
   ENCS1DRAM=0 and PA 0 decodes DRAM BANK 0 (TMPR3911/3912 §4.7.1, Table 4.2.1).
   Bit 0 is CS0SIZE and carries the reset strap through untouched. */
constexpr uint32_t kDramPaBase = 0x00000000u;

/* Same write: BANK0CONF=00 (16-bit), ROWSEL0=00 (10 row bits), COLSEL0=0000
   (11 col bits) -> 2^21 cells x 16 bit (TMPR3911/3912 §4.7.1). */
constexpr uint32_t kDramSize = 0x00400000u;

/* Table 4.2.1 gives DRAM BANK 0 a 32 MB decode at PA 0. The populated part is
   smaller, so the address bits above it are never presented and it repeats.
   nk.exe sub_9F4117B4 reads PA 0x00C00000 back to size the part. */
constexpr uint32_t kDramDecodeSpan = 0x02000000u;

class PhilipsNino300PageTableBuilder : public MipsKsegDramRomPageTableBuilder {
public:
    explicit PhilipsNino300PageTableBuilder(CerfEmulator& emu)
        : MipsKsegDramRomPageTableBuilder(emu, {
              { kDramVaBase, kDramPaBase, kDramSize }, kDramDecodeSpan, kDramDecodeSpan,
          }) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsNino300;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(PhilipsNino300PageTableBuilder, PageTableBuilder);
