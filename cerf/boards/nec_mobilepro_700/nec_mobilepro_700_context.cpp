#include "../board_context.h"

#include "nec_mobilepro_700_id.h"
#include "../../core/cerf_emulator.h"

namespace {

class NecMobilePro700Context : public BoardContext {
public:
    using BoardContext::BoardContext;

    std::string_view GetBoardId() const override { return BoardId::NecMobilepro700; }

    /* VR4102 "reserved for future use" span, UM Table 5-6: 0x04000000-0x09FFFFFF (96 MB). */
    uint32_t GuestAdditionsWindowBase() const override { return 0x04000000u; }
    uint32_t GuestAdditionsWindowSize() const override { return 0x06000000u; }
};

}

REGISTER_SERVICE_AS(NecMobilePro700Context, BoardContext);
