#include "../mips_kseg_dram_rom_page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "casio_toricomail_id.h"

#include <cstdint>

namespace {

/* DRAM Area PA 0x00000000-0x07FFFFFF (VR4121 UM Fig 6-8); ROMHDR ulRAMStart/ulRAMEnd
   place this board's populated DRAM at kseg0 0x80000000, 8 MB. */
constexpr uint32_t kDramVaBase = 0x80000000u;
constexpr uint32_t kDramPaBase = 0x00000000u;
constexpr uint32_t kDramSize   = 0x00800000u;   /* 8 MB (ROMHDR ulRAMEnd 0x80800000) */

/* ROM Area (incl. Boot ROM) PA 0x18000000-0x1FFFFFFF (VR4121 UM Fig 6-8). The CE XIP
   is at ROMHDR physfirst = kseg0 0x9F000000 -> PA 0x1F000000; the flat's own 0xC00000
   offset lands on the MIPS reset vector PA 0x1FC00000, where the Casio base monitor
   XIP sits. */
constexpr uint32_t kRomVaBase  = 0x9F000000u;
constexpr uint32_t kRomPaBase  = 0x1F000000u;
constexpr uint32_t kRomSize    = 0x01000000u;   /* 16 MB */

class CasioToricomailPageTableBuilder : public MipsKsegDramRomPageTableBuilder {
public:
    explicit CasioToricomailPageTableBuilder(CerfEmulator& emu)
        : MipsKsegDramRomPageTableBuilder(emu, {
              { kDramVaBase, kDramPaBase, kDramSize }, 0u, kDramSize,
          }, { kRomVaBase, kRomPaBase, kRomSize }) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::CasioToricomail;
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioToricomailPageTableBuilder, PageTableBuilder);
