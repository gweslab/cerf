#include "../../boot/guest_cold_boot.h"
#include "../../boot/rom_placer.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/service.h"
#include "../../cpu/emulated_memory.h"
#include "../board_context.h"
#include "siemens_p177_id.h"

#include <array>
#include <cstdint>
#include <cstring>

/* Siemens P177 coupled-bootloader HW-info handoff. CERF skips the P177
   bootloader (agent_docs/boot_loaders.md), so without this synthesised 128-byte
   block + flash-0x20 pointer the OAL parser (nk.exe sub_8304579C, oemhwinf.c)
   aborts firmware init. Struct offset N -> global 0x8011F4F8+N. */

namespace {

/* Flash offset 0x20 (nGCS0 PA 0x20): the pointer cell OALInitHwInfo reads. */
constexpr uint32_t kHwInfoPointerPa = 0x00000020u;

/* nGCS0 PA 0x800: free zero padding (0x4B..0x1004, between ROM header and the
   first XIP module). MUST stay in the first 4 MiB the parser range-checks and
   off live image bytes - the contributor's 0x3F0000 overwrites module .text. */
constexpr uint32_t kHwInfoPa   = 0x00000800u;
constexpr size_t   kHwInfoSize = 128u;

class SiemensP177BootloaderHwi : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SiemensP177;
    }

    void OnReady() override {
        /* The block lives in NOR, so place the ROM first, then overlay the
           handoff the bootloader would have written. */
        (void)emu_.Get<RomPlacer>();
        WriteHwi();
        emu_.Get<GuestColdBoot>().RegisterReplay([this] { WriteHwi(); });
    }

private:
    void WriteHwi() {
        std::array<uint8_t, kHwInfoSize> hwi{};

        auto put16 = [&](size_t off, uint16_t v) { cerf::le::Put16(hwi.data() + off, v); };

        /* Block copied verbatim to 0x8011F4F8; offset N -> global 0x8011F4F8+N. */
        hwi[0x00] = 0xA5u;     /* 0x8011F4F8 leading signature                  */
        hwi[0x01] = 0x21u;     /* 0x8011F4F9 count=1, blk-count shift=2 (bits4-5),
                                  blk-size shift=0 (bits6-7)                     */
        put16(0x02, 0x0000u);  /* 0x8011F4FA flash base hi16 -> base 0xA4000000 */
        hwi[0x06] = 128u;      /* 0x8011F4FE block count: sub_83045BE8 returns
                                  (1<<bits[5:4])*this = 4*128 = 512 (32 MB/64KiB)*/
        hwi[0x0A] = 64u;       /* 0x8011F502 sector size: sub_83045C58 returns
                                  (1024<<bits[7:6])*this = 64 KiB                */
        put16(0x04, 0x8000u);  /* 0x8011F4FC flash size = 32 MiB (nGCS0 OAT decode;
                                  sub_8304630C: (this&0xFFFC)<<10). OAL carves a fixed
                                  15 MiB OS (sub_830465C0); FFS=flashSize-15 MiB, and
                                  FFS<2 MiB zero-sizes partition 1 -> vlbd.cpp:675.  */
        put16(0x0E, 0x0000u);  /* 0x8011F506 OS-region prefix = 0 KiB           */
        hwi[0x12] = 0x07u;     /* 0x8011F50A flash type = 7 (probe accept gate) */
        hwi[0x13] = 0x05u;     /* 0x8011F50B panel = 5: family 1/subtype 256/panel 5 ->
                                  OAL sub_83045D88 gives 480x272x8 (panel!=5 -> 320x240);
                                  480x272 = the driver's hardcoded 130560-byte fb (480*272) */
        hwi[0x28] = 0x01u;     /* 0x8011F520 LCD family = 1                      */
        put16(0x2C, 0x0100u);  /* 0x8011F524 LCD subtype = 256 (-> 480x272x8 w/ panel 5) */
        hwi[0x7F] = 0x5Au;     /* 0x8011F577 trailing signature                 */

        auto& mem = emu_.Get<EmulatedMemory>();
        mem.CopyIn(kHwInfoPa, hwi.data(), hwi.size());
        mem.WriteWord(kHwInfoPointerPa, kHwInfoPa);

        LOG(Board, "SiemensP177BootloaderHwi: HWI at PA 0x%08X (ptr@0x%02X), "
                   "flash base 0xA4000000 size 32 MiB type 7, LCD 480x272x8\n",
            kHwInfoPa, kHwInfoPointerPa);
    }
};

}  // namespace

REGISTER_SERVICE(SiemensP177BootloaderHwi);
