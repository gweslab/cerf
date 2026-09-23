#include "../page_table_builder.h"

#include "../../boot/rom_parser_service.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "philips_velo_1_id.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t kKseg0Base  = 0x80000000u;
constexpr uint32_t kKseg1Base  = 0xA0000000u;
constexpr uint32_t kKseg2Base  = 0xC0000000u;
constexpr uint32_t kUnmaskKseg = 0x1FFFFFFFu;

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

class PhilipsVelo1PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
    }

    void OnReady() override {
        auto& rom = emu_.Get<RomParserService>();
        if (!rom.Ok() || rom.Loaded().empty() || rom.Primary().xips.empty()) {
            LOG(Caution, "PhilipsVelo1PageTableBuilder: ROM not parsed\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const ParsedRom& prim = rom.Primary();

        /* Both XIPs are resident in the same CS0 flash, so the backed region spans
           the first XIP's physfirst to the last XIP's physlast. */
        uint32_t rom_va_base = 0xFFFFFFFFu;
        uint32_t rom_va_end  = 0u;
        for (const auto& xip : prim.xips) {
            const ParsedROMHDR& h = xip.toc.romhdr;
            if (h.physfirst < rom_va_base) rom_va_base = h.physfirst;
            if (h.physlast  > rom_va_end)  rom_va_end  = h.physlast;
        }

        if (rom_va_base < kKseg0Base || rom_va_end <= rom_va_base ||
            rom_va_end > kKseg1Base) {
            LOG(Caution, "PhilipsVelo1PageTableBuilder: ROM outside kseg0: "
                    "base=0x%08X end=0x%08X\n", rom_va_base, rom_va_end);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const ParsedROMHDR* hdr = prim.XipHeaderContaining(prim.entry_va);
        if (!hdr) {
            LOG(Caution, "PhilipsVelo1PageTableBuilder: entry VA 0x%08X lies in no "
                    "XIP\n", prim.entry_va);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        if (hdr->ulRAMEnd <= kDramVaBase ||
            hdr->ulRAMEnd - kDramVaBase > kDramSize) {
            LOG(Caution, "PhilipsVelo1PageTableBuilder: ROMHDR ulRAMEnd 0x%08X does "
                    "not fit DRAM BANK 0 (0x%X bytes)\n", hdr->ulRAMEnd, kDramSize);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        rom_va_base_ = rom_va_base;
        rom_pa_base_ = rom_va_base & kUnmaskKseg;
        rom_size_    = rom_va_end - rom_va_base;

        LOG(Boot, "PhilipsVelo1PageTableBuilder: ROM kva=0x%08X pa=0x%08X size=0x%X, "
                  "DRAM pa=0x%08X size=0x%X span=0x%X (ulRAMEnd=0x%08X)\n",
            rom_va_base_, rom_pa_base_, rom_size_, kDramPaBase, kDramSize,
            kDramDecodeSpan, hdr->ulRAMEnd);
    }

    uint32_t VaToPa(uint32_t va) const override {
        if (va >= kKseg0Base && va < kKseg2Base) {
            return va & kUnmaskKseg;
        }
        LOG(Caution, "PhilipsVelo1PageTableBuilder::VaToPa: VA 0x%08X is outside the "
                "kseg0/kseg1 unmapped windows\n", va);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
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
            { rom_va_base_, rom_pa_base_, rom_size_,  PAGE_EXECUTE_READ },
        };
    }

    std::vector<DramRegion> MappedVaSpans() const override {
        return {
            { kDramVaBase,  kDramPaBase,  kDramDecodeSpan },
            { kBank1VaBase, kBank1PaBase, kBank1DecodeSpan },
            { rom_va_base_, rom_pa_base_, rom_size_ },
            { kRegsVaBase,  kRegsPaBase,  kRegsSize },
        };
    }

private:
    uint32_t rom_va_base_ = 0;
    uint32_t rom_pa_base_ = 0;
    uint32_t rom_size_    = 0;
};

}  /* namespace */

REGISTER_SERVICE_AS(PhilipsVelo1PageTableBuilder, PageTableBuilder);
