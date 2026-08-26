#include "simpad_sl4_boot.h"

#include "../board_context.h"
#include "../../boot/board_boot_placer.h"
#include "../../boot/rom_parser_queries.h"
#include "../../boot/rom_parser_service.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>
#include <span>

namespace {

class SimpadSl4BootPlacer : public BoardBootPlacer {
public:
    using BoardBootPlacer::BoardBootPlacer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SimpadSl4;
    }

    void PlaceAfterRom() override {
        auto& parser = emu_.Get<RomParserService>();
        if (!parser.Ok() || parser.Primary().xips.empty()) {
            LOG(Caution, "SimpadSl4BootPlacer: no parsed XIP; cannot place "
                         "boot head copy-source\n");
            return;
        }

        const uint32_t physfirst =
            parser.Primary().xips[0].toc.romhdr.physfirst;
        std::span<const uint8_t> head =
            emu_.Get<RomParserQueries>().ReadVa(physfirst,
                                               simpad_sl4::kHeadLen);
        if (head.size() < simpad_sl4::kHeadLen) {
            LOG(Caution, "SimpadSl4BootPlacer: head VA 0x%08X len 0x%X not "
                         "fully in any partition (got 0x%zX)\n",
                physfirst, simpad_sl4::kHeadLen, head.size());
            return;
        }

        emu_.Get<EmulatedMemory>().CopyIn(
            simpad_sl4::kHeadCopySrcPa, head.data(), head.size());
        LOG(Boot, "SimpadSl4BootPlacer: image head 0x%X bytes -> flash "
                  "copy-source pa=0x%08X (boot stub copies it to DRAM)\n",
            simpad_sl4::kHeadLen, simpad_sl4::kHeadCopySrcPa);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(SimpadSl4BootPlacer, BoardBootPlacer);
