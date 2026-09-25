#include "../vr41xx/vr41xx_reg_window_impl.h"

#include <cstdint>
#include "vr4121_id.h"

namespace {

using cerf_vr41xx_reg_window_detail::OtherReset;
using cerf_vr41xx_reg_window_detail::ReadKind;
using cerf_vr41xx_reg_window_detail::Vr41xxRegWindowBase;
using cerf_vr41xx_reg_window_detail::Vr41xxRegWindowModel;
using cerf_vr41xx_reg_window_detail::WriteKind;

/* VR4121 BCU (Bus Control Unit), Internal I/O Space 2 (UM Table 1-1). The DMAAU
   block follows at 0x0B000020 (UM Table 1-2), so the BCU decodes 0x0B000000-1F. */
constexpr Vr41xxRegWindowModel kModel = {
    /*base=*/0x0B000000u,
    /*size=*/0x20u,
    14u,
    /*word_pairs=*/false,
    {
        /* 0x00 BCUCNTREG1 (UM 11.2.1): R/W bits D15/14/13/12/10/8/6/4/3/2/1/0,
           RFU-read-0 D11/9/7/5; RTCRST/After-reset 0 except D14 (Note 1 board DRAM
           strap, unmodeled). casio_toricomail_ce212 MMCRestore.exe 0x12B7C RMWs it
           without branching (set D6 ROMWEN2, clear D10 PAGEROM2). */
        { ReadKind::kStored, WriteKind::kStored, 0xF55Fu, 0x0000u, 0u },
        {},
        {},
        {},
        {},
        {},
        /* 0x0C BCUERRSTREG (UM 11.2.6): D0 BERRST, "Bus error status. Clear to 0 when
           1 is written."; D15:1 RFU, "Write 0 to these bits. 0 is returned after a
           read." CERF raises no bus errors, so a read has no grounded value. */
        { ReadKind::kFatal, WriteKind::kClear, 0x0001u, 0x0000u, 0u },
        /* 0x0E BCURFCNTREG (UM 11.2.7): D13:0 BRF(13:0), "Number of DRAM refresh
           cycles (with TClock cycle)"; D15:14 RFU read 0. RTCRST column = BRF9; the
           After-reset row is "Value before reset is retained". */
        { ReadKind::kStored, WriteKind::kStored, 0x3FFFu, 0x0200u, 0u, OtherReset::kRetain },
        {},
        {},
        {},
        /* 0x16 BCUCNTREG3 (UM 11.2.11): R/W D15:11/D7; D2:0 print "R" but UM 11.4.6 +
           casio_toricomail_ce212 nk.exe 0x9F0B5B80 (`lhu;ori 7;sh`) write LCDSEL/BSEL;
           D10:8/D6:3 RFU read-0; RTCRST 0 except D14 (Note 1 SDRAM strap, unmodeled);
           After-reset row "Value before reset is retained". */
        { ReadKind::kStored, WriteKind::kStored, 0xF887u, 0x0000u, 0u, OtherReset::kRetain },
        {},
        /* 0x1A SDRAMMODEREG (UM 11.2.12): R/W D15 SCLK, D6:4 LTMODE; D3 WT, D2:0 BL read
           1 and 001; D14:7 RFU read 0; RTCRST 0x8039; After-reset "retained". */
        { ReadKind::kStored, WriteKind::kStored, 0x8070u, 0x8039u, 0u, OtherReset::kRetain },
    },
};

static_assert((0xF55Fu & 0x0AA0u) == 0u,
              "BCUCNTREG1 writable and read-0 RFU bits overlap");
static_assert((0xF887u & 0x0778u) == 0u,
              "BCUCNTREG3 writable and read-0 RFU bits overlap");
static_assert((0x8070u & 0x7F80u) == 0u,
              "SDRAMMODEREG writable and read-0 RFU bits overlap");

constexpr uint32_t kOffSdramMode = 0x1Au;

constexpr bool LtmodeDefined(uint16_t value) {
    const uint16_t ltmode = static_cast<uint16_t>((value >> 4) & 0x7u);
    return ltmode == 0x2u || ltmode == 0x3u;
}

class Vr4121Bcu : public Vr41xxRegWindowBase<SocId::Vr4121, kModel> {
public:
    using Vr41xxRegWindowBase::Vr41xxRegWindowBase;

    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (addr - kModel.base == kOffSdramMode && !LtmodeDefined(value)) {
            HaltUnsupportedAccess("SDRAMMODEREG WriteHalf with an RFU LTMODE", addr, value);
        }
        Vr41xxRegWindowBase::WriteHalf(addr, value);
    }
};

}

REGISTER_SERVICE(Vr4121Bcu);
