#include "../mips_kseg_page_table_builder.h"

#include "../../boot/rom_parser_service.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "philips_velo_1_id.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t kDramVaBase = 0x80000000u;

/* nk.exe sub_9F40EA9C leaves ENCS1DRAM clear (MEMCONFIG0 &= 0x010FFFF1), so PA 0
   decodes DRAM BANK 0 (TMPR3911 Table 4.2.1). */
constexpr uint32_t kDramPaBase = 0x00000000u;

/* The Philips Velo 1 ships 4 MB of EDO DRAM (OEM specification). nk.exe
   sub_9F40EAE0 measures DRAM by aliasing, so the guest adopts whatever size is
   populated here. */
constexpr uint32_t kDramSize = 0x00400000u;

/* DRAM BANK 0 decodes 32 MB at PA 0 (TMPR3911 Table 4.2.1); the 4 MB population
   aliases through the window, which is how sub_9F40EAE0 sizes it. */
constexpr uint32_t kDramDecodeSpan = 0x02000000u;

/* The 16 Mbyte DRAM Miniature Card fitted in slot 1. philips_velo_1_ce1 nk.exe
   sub_9F42453C @0x9F42453C reports its base as 0x82000000 and the kernel takes it as a
   second RAM region (sub_9F4155C0 @0x9F4155C0); PA 0x02000000 decodes DRAM BANK 1 over
   32 MB while ENCS1DRAM is clear (TMPR3911 Table 4.2.1). */
constexpr uint32_t kBank1VaBase     = 0x82000000u;
constexpr uint32_t kBank1PaBase     = 0x02000000u;
constexpr uint32_t kBank1Size       = 0x01000000u;
constexpr uint32_t kBank1DecodeSpan = 0x02000000u;

/* Internal Function Registers, 2 MB at PA 0x10C00000 (TMPR3911 Table 4.2.1). */
constexpr uint32_t kRegsPaBase = 0x10C00000u;
constexpr uint32_t kRegsVaBase = 0xB0C00000u;
constexpr uint32_t kRegsSize   = 0x00200000u;

class PhilipsVelo1PageTableBuilder : public MipsKsegPageTableBuilder {
public:
    using MipsKsegPageTableBuilder::MipsKsegPageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
    }

    void OnReady() override {
        const ParsedRom& prim = PrimaryRom();

        /* Both XIPs are resident in the same CS0 flash, so the backed region spans
           the first XIP's physfirst to the last XIP's physlast. */
        uint32_t rom_va_base = 0xFFFFFFFFu;
        uint32_t rom_va_end  = 0u;
        for (const auto& xip : prim.xips) {
            const ParsedROMHDR& h = xip.toc.romhdr;
            if (h.physfirst < rom_va_base) rom_va_base = h.physfirst;
            if (h.physlast  > rom_va_end)  rom_va_end  = h.physlast;
        }

        rom_ = Kseg0RomSpan(rom_va_base, rom_va_end);

        const ParsedROMHDR* hdr = prim.XipHeaderContaining(prim.entry_va);
        if (!hdr) {
            emu_.Get<Fatal>().Die("PhilipsVelo1PageTableBuilder: entry VA 0x%08X lies "
                                  "in no XIP", prim.entry_va);
        }

        RequireRamEndWithin(*hdr, kDramVaBase, kDramSize);

        LOG(Boot, "PhilipsVelo1PageTableBuilder: ROM kva=0x%08X pa=0x%08X size=0x%X, "
                  "DRAM pa=0x%08X size=0x%X span=0x%X (ulRAMEnd=0x%08X)\n",
            rom_.va_base, rom_.pa_base, rom_.size, kDramPaBase, kDramSize,
            kDramDecodeSpan, hdr->ulRAMEnd);
    }

    std::vector<DramRegion> CachedDramRegions() const override {
        return {
            { kDramVaBase,  kDramPaBase,  kDramSize },
            { kBank1VaBase, kBank1PaBase, kBank1Size },
        };
    }

    std::vector<BackedRegion> BackedMemoryRegions() const override {
        return {
            { kDramVaBase,  kDramPaBase,  kDramSize,  PAGE_READWRITE, kDramDecodeSpan },
            { kBank1VaBase, kBank1PaBase, kBank1Size, PAGE_READWRITE, kBank1DecodeSpan },
            { rom_.va_base, rom_.pa_base, rom_.size,  PAGE_EXECUTE_READ },
        };
    }

    std::vector<DramRegion> MappedVaSpans() const override {
        return {
            { kDramVaBase,  kDramPaBase,  kDramDecodeSpan },
            { kBank1VaBase, kBank1PaBase, kBank1DecodeSpan },
            rom_,
            { kRegsVaBase,  kRegsPaBase,  kRegsSize },
        };
    }

private:
    DramRegion rom_{};
};

}  /* namespace */

REGISTER_SERVICE_AS(PhilipsVelo1PageTableBuilder, PageTableBuilder);
