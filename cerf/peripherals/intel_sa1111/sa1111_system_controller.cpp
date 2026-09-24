#include "sa1111_system_controller.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool Sa1111SystemController::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111SystemController::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Sa1111SystemController::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off <= 0x20u && (off & 3u) == 0) return regs_[off >> 2];
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1111SystemController::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off <= 0x20u && (off & 3u) == 0) { regs_[off >> 2] = value; return; }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Sa1111SystemController::SaveState(StateWriter& w) {
    w.WriteBytes("regs", regs_, sizeof(regs_));
}

void Sa1111SystemController::RestoreState(StateReader& r) {
    r.ReadBytes("regs", regs_, sizeof(regs_));
}

REGISTER_SERVICE(Sa1111SystemController);
