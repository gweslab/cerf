#include "nec_mobilepro_900_boot_args.h"

#include "../board_context.h"
#include "nec_mobilepro_900_id.h"
#include "../../boot/rom_parser_queries.h"
#include "../../core/cerf_emulator.h"

bool NecMobilepro900BootArgs::BoardMatchesKernelMajor(uint16_t major) const {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd || bd->GetBoardId() != BoardId::NecMobilepro900) return false;
    uint16_t maj = 0, min = 0;
    return emu_.Get<RomParserQueries>().KernelSubsystemVersion(maj, min) && maj == major;
}
