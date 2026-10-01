#include "imx51_power_gate_line.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "imx51_id.h"

#include <utility>

REGISTER_SERVICE(Imx51PowerGateLine);

bool Imx51PowerGateLine::ShouldRegister() {
    return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
}

void Imx51PowerGateLine::RegisterBlock(Imx51PowerGatedBlock block,
                                       std::function<void()> power_down) {
    auto& slot = blocks_[static_cast<size_t>(block)];
    if (slot) {
        emu_.Get<Fatal>().Die("Imx51PowerGateLine: block %u registered twice",
                              static_cast<unsigned>(block));
    }
    slot = std::move(power_down);
}

void Imx51PowerGateLine::PowerDown(Imx51PowerGatedBlock block) {
    const auto& slot = blocks_[static_cast<size_t>(block)];
    if (!slot) {
        emu_.Get<Fatal>().Die("Imx51PowerGateLine: block %u is power-gated with no model "
                              "registered for it", static_cast<unsigned>(block));
    }
    slot();
}
