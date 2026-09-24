#include "../mips_kseg_page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "sharp_mobilon_hc4100_id.h"

#include <cstdint>
#include <vector>

namespace {

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

class SharpMobilonHc4100PageTableBuilder : public MipsKsegPageTableBuilder {
public:
    using MipsKsegPageTableBuilder::MipsKsegPageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SharpMobilonHc4100;
    }

    void OnReady() override {
        rom_ = PlaceEntryXipRom(kDramVaBase, kBank0Size);
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
            { rom_.va_base, rom_.pa_base, rom_.size,  PAGE_EXECUTE_READ },
        };
    }

    std::vector<DramRegion> MappedVaSpans() const override {
        return {
            { kDramVaBase,  kBank0PaBase, kBank0DecodeSpan },
            { kBank1VaBase, kBank1PaBase, kBank1DecodeSpan },
            rom_,
            { kRegsVaBase,  kRegsPaBase,  kRegsSize },
        };
    }

private:
    DramRegion rom_{};
};

}  /* namespace */

REGISTER_SERVICE_AS(SharpMobilonHc4100PageTableBuilder, PageTableBuilder);
