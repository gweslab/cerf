#include "../mips_kseg_page_table_builder.h"

#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_mmu.h"
#include "../board_context.h"
#include "nec_rockhopper_id.h"

#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t kDramPaBase = 0x00000000u;
constexpr uint32_t kDramSize   = 0x08000000u;   /* 128 MB */
constexpr uint32_t kDramVaBase = MipsSeg::kKusegEnd | kDramPaBase;

class NecRockhopperPageTableBuilder : public MipsKsegPageTableBuilder {
public:
    using MipsKsegPageTableBuilder::MipsKsegPageTableBuilder;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecRockhopper;
    }

    std::vector<DramRegion> CachedDramRegions() const override {
        return { { kDramVaBase, kDramPaBase, kDramSize } };
    }

    std::vector<BackedRegion> BackedMemoryRegions() const override {
        return { { kDramVaBase, kDramPaBase, kDramSize, PAGE_READWRITE } };
    }

    std::vector<DramRegion> MappedVaSpans() const override {
        return { { kDramVaBase, kDramPaBase, kDramSize } };
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(NecRockhopperPageTableBuilder, PageTableBuilder);
