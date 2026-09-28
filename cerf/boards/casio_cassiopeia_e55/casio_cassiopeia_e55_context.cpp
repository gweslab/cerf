#include "../board_context.h"

#include "casio_cassiopeia_e55_id.h"
#include "../../core/cerf_emulator.h"

namespace {

class CasioCassiopeiaE55Context : public BoardContext {
public:
    using BoardContext::BoardContext;

    std::string_view GetBoardId() const override { return BoardId::CasioCassiopeiaE55; }

    /* VR4111 UM Table 6-6 p166 types 0x0D000000 to 0x0FFFFFFF as space reserved for
       future use, 48 M. */
    uint32_t GuestAdditionsWindowBase() const override { return 0x0D000000u; }
    uint32_t GuestAdditionsWindowSize() const override { return 0x03000000u; }
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioCassiopeiaE55Context, BoardContext);
