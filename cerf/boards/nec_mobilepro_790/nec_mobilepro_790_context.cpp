#include "../board_context.h"

#include "nec_mobilepro_790_id.h"
#include "../../core/cerf_emulator.h"

namespace {

class NecMobilePro790Context : public BoardContext {
public:
    using BoardContext::BoardContext;

    std::string_view GetBoardId() const override { return BoardId::NecMobilepro790; }
};

}

REGISTER_SERVICE_AS(NecMobilePro790Context, BoardContext);
