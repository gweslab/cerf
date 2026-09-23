#include "../page_table_builder.h"

#include "../../boot/rom_parser_service.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "philips_nino_300_id.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t kKseg0Base  = 0x80000000u;
constexpr uint32_t kKseg1Base  = 0xA0000000u;
constexpr uint32_t kKseg2Base  = 0xC0000000u;
constexpr uint32_t kUnmaskKseg = 0x1FFFFFFFu;

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

class PhilipsNino300PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsNino300;
    }

    void OnReady() override {
        auto& rom = emu_.Get<RomParserService>();
        if (!rom.Ok() || rom.Loaded().empty() || rom.Primary().xips.empty()) {
            LOG(Caution, "PhilipsNino300PageTableBuilder: ROM not parsed\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const ParsedRom&    prim = rom.Primary();
        const ParsedROMHDR* hdr  = prim.XipHeaderContaining(prim.entry_va);
        if (!hdr) {
            hdr = &prim.xips.front().toc.romhdr;
        }

        if (hdr->physfirst < kKseg0Base || hdr->physlast <= hdr->physfirst ||
            hdr->physlast > kKseg1Base) {
            LOG(Caution, "PhilipsNino300PageTableBuilder: ROM outside kseg0: "
                    "physfirst=0x%08X physlast=0x%08X\n",
                hdr->physfirst, hdr->physlast);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        if (hdr->ulRAMEnd <= kDramVaBase ||
            hdr->ulRAMEnd - kDramVaBase > kDramSize) {
            LOG(Caution, "PhilipsNino300PageTableBuilder: ROMHDR ulRAMEnd 0x%08X "
                    "does not fit DRAM BANK 0 (0x%X bytes)\n",
                hdr->ulRAMEnd, kDramSize);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        rom_va_base_ = hdr->physfirst;
        rom_pa_base_ = hdr->physfirst & kUnmaskKseg;
        rom_size_    = hdr->physlast - hdr->physfirst;

        LOG(Boot, "PhilipsNino300PageTableBuilder: ROM kva=0x%08X pa=0x%08X size=0x%X, "
                  "DRAM pa=0x%08X size=0x%X (ulRAMEnd=0x%08X)\n",
            rom_va_base_, rom_pa_base_, rom_size_, kDramPaBase, kDramSize,
            hdr->ulRAMEnd);
    }

    uint32_t VaToPa(uint32_t va) const override {
        if (va >= kKseg0Base && va < kKseg2Base) {
            return va & kUnmaskKseg;
        }
        LOG(Caution, "PhilipsNino300PageTableBuilder::VaToPa: VA 0x%08X is "
                "outside the kseg0/kseg1 unmapped windows\n", va);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    std::vector<DramRegion> CachedDramRegions() const override {
        return { { kDramVaBase, kDramPaBase, kDramSize } };
    }

    std::vector<BackedRegion> BackedMemoryRegions() const override {
        return {
            { kDramVaBase,  kDramPaBase,  kDramSize, PAGE_READWRITE, kDramDecodeSpan },
            { rom_va_base_, rom_pa_base_, rom_size_, PAGE_EXECUTE_READ },
        };
    }

    std::vector<DramRegion> MappedVaSpans() const override {
        return {
            { kDramVaBase,  kDramPaBase,  kDramDecodeSpan },
            { rom_va_base_, rom_pa_base_, rom_size_ },
        };
    }

private:
    uint32_t rom_va_base_ = 0;
    uint32_t rom_pa_base_ = 0;
    uint32_t rom_size_    = 0;
};

}  /* namespace */

REGISTER_SERVICE_AS(PhilipsNino300PageTableBuilder, PageTableBuilder);
