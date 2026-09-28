#include "sa11xx_core_clock_table.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "sa1110_id.h"

namespace {

class Sa1110CoreClockTable : public Sa11xxCoreClockTable {
public:
    using Sa11xxCoreClockTable::Sa11xxCoreClockTable;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Sa1110;
    }

    /* SA-1110 Dev Man printed 8-2 Table 8-1: 01011 = 221.2 MHz, 01100-11111 not supported. */
    uint32_t MaxCcf() const override { return 0x0Bu; }
};

}

REGISTER_SERVICE_AS(Sa1110CoreClockTable, Sa11xxCoreClockTable);
