#include "page_table_builder.h"

#include "board_detector.h"
#include "../core/cerf_emulator.h"

namespace {

class NullPageTableBuilder : public PageTableBuilder {
public:
    using PageTableBuilder::PageTableBuilder;

    bool ShouldRegister() override {
        return emu_.Get<BoardDetector>().GetBoard() == Board::Unknown;
    }

    uint32_t InitStackTopPa() const override { return 0; }
    uint32_t VaToPa(uint32_t va) const override { return va; }
    std::vector<DramRegion>   CachedDramRegions()   const override { return {}; }
    std::vector<BackedRegion> BackedMemoryRegions() const override { return {}; }
};

}  /* namespace */

REGISTER_SERVICE_AS(NullPageTableBuilder, PageTableBuilder);
