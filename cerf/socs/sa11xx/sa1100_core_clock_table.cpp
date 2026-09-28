#include "sa11xx_core_clock_table.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "sa1100_id.h"

namespace {

class Sa1100CoreClockTable : public Sa11xxCoreClockTable {
public:
    using Sa11xxCoreClockTable::Sa11xxCoreClockTable;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Sa1100;
    }

    /* SA-1100 TRM printed 8-2 Table 8-1: 01010 = 206.4 MHz, 01011-11111 not supported. */
    uint32_t MaxCcf() const override { return 0x0Au; }
};

}

REGISTER_SERVICE_AS(Sa1100CoreClockTable, Sa11xxCoreClockTable);
