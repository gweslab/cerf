#include "../page_table_builder.h"

#include "../../boot/rom_parser_service.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "sharp_mobilon_hc4100_id.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t kKseg0Base  = 0x80000000u;
constexpr uint32_t kKseg1Base  = 0xA0000000u;
constexpr uint32_t kKseg2Base  = 0xC0000000u;
constexpr uint32_t kUnmaskKseg = 0x1FFFFFFFu;

constexpr uint32_t kDramVaBase = 0x80000000u;

/* TX39 BIU System Address Map: DRAMBANK0CS1 0x00000000, DRAMBANK1CS1 0x02000000,
   DRAMBANK_LEN 0x02000000 (ENCS1DRAM clear). */
constexpr uint32_t kBank0PaBase     = 0x00000000u;
constexpr uint32_t kBank0DecodeSpan = 0x02000000u;
constexpr uint32_t kBank1VaBase     = 0x82000000u;
constexpr uint32_t kBank1PaBase     = 0x02000000u;
constexpr uint32_t kBank1DecodeSpan = 0x02000000u;

/* 12 MiB (PhoneDB id=235 / hpcfactor device 151); nk.exe sub_910231E0 sizes RAM
   from TX39 MEMCONFIG0: &0x330F0 (BANK0CONF/ROWSEL0/COLSEL0) = 4 MiB,
   &0xCCF00 (BANK1CONF/ROWSEL1/COLSEL1) = 8 MiB. */
constexpr uint32_t kBank0Size = 0x00400000u;
constexpr uint32_t kBank1Size = 0x00800000u;

/* TX39 BIU CONFIG_REG 0x10C00000, len 0x00200000; kseg1 VA 0xB0C00000. */
constexpr uint32_t kRegsVaBase = 0xB0C00000u;
constexpr uint32_t kRegsPaBase = 0x10C00000u;
constexpr uint32_t kRegsSize   = 0x00200000u;

class SharpMobilonHc4100PageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SharpMobilonHc4100;
    }

    void OnReady() override {
        auto& rom = emu_.Get<RomParserService>();
        if (!rom.Ok() || rom.Loaded().empty() || rom.Primary().xips.empty()) {
            LOG(Caution, "SharpMobilonHc4100PageTableBuilder: ROM not parsed\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const ParsedRom&    prim = rom.Primary();
        const ParsedROMHDR* hdr  = prim.XipHeaderContaining(prim.entry_va);
        if (!hdr) {
            hdr = &prim.xips.front().toc.romhdr;
        }

        if (hdr->physfirst < kKseg0Base || hdr->physlast <= hdr->physfirst ||
            hdr->physlast > kKseg1Base) {
            LOG(Caution, "SharpMobilonHc4100PageTableBuilder: ROM outside kseg0: "
                    "physfirst=0x%08X physlast=0x%08X\n",
                hdr->physfirst, hdr->physlast);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        if (hdr->ulRAMEnd <= kDramVaBase ||
            hdr->ulRAMEnd - kDramVaBase > kBank0Size) {
            LOG(Caution, "SharpMobilonHc4100PageTableBuilder: ROMHDR ulRAMEnd 0x%08X "
                    "does not fit DRAM BANK 0 (0x%X bytes)\n",
                hdr->ulRAMEnd, kBank0Size);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        rom_va_base_ = hdr->physfirst;
        rom_pa_base_ = hdr->physfirst & kUnmaskKseg;
        rom_size_    = hdr->physlast - hdr->physfirst;

        LOG(Boot, "SharpMobilonHc4100PageTableBuilder: ROM kva=0x%08X pa=0x%08X "
                  "size=0x%X, DRAM bank0 pa=0x%08X size=0x%X, bank1 pa=0x%08X "
                  "size=0x%X (ulRAMEnd=0x%08X)\n",
            rom_va_base_, rom_pa_base_, rom_size_, kBank0PaBase, kBank0Size,
            kBank1PaBase, kBank1Size, hdr->ulRAMEnd);
    }

    uint32_t VaToPa(uint32_t va) const override {
        if (va >= kKseg0Base && va < kKseg2Base) {
            return va & kUnmaskKseg;
        }
        LOG(Caution, "SharpMobilonHc4100PageTableBuilder::VaToPa: VA 0x%08X is "
                "outside the kseg0/kseg1 unmapped windows\n", va);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    std::vector<DramRegion> CachedDramRegions() const override {
        return {
            { kDramVaBase,  kBank0PaBase, kBank0Size },
            { kBank1VaBase, kBank1PaBase, kBank1Size },
        };
    }

    std::vector<BackedRegion> BackedMemoryRegions() const override {
        return {
            { kDramVaBase,  kBank0PaBase, kBank0Size, PAGE_READWRITE, kBank0DecodeSpan },
            { kBank1VaBase, kBank1PaBase, kBank1Size, PAGE_READWRITE, kBank1DecodeSpan },
            { rom_va_base_, rom_pa_base_, rom_size_, PAGE_EXECUTE_READ },
        };
    }

    std::vector<DramRegion> MappedVaSpans() const override {
        return {
            { kDramVaBase,  kBank0PaBase, kBank0DecodeSpan },
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

REGISTER_SERVICE_AS(SharpMobilonHc4100PageTableBuilder, PageTableBuilder);
