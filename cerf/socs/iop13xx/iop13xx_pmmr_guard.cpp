#include "iop13xx_pmmr_guard.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"

bool Iop13xxPmmrGuard::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetSoc() == SocFamily::IOP13xx;
}

void Iop13xxPmmrGuard::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Iop13xxPmmrGuard::ReadWord(uint32_t addr) {
    HaltUnsupportedAccess("IOP13xx unsupported PMMR word read", addr, 0);
}

uint16_t Iop13xxPmmrGuard::ReadHalf(uint32_t addr) {
    HaltUnsupportedAccess("IOP13xx unsupported PMMR halfword read", addr, 0);
}

uint8_t Iop13xxPmmrGuard::ReadByte(uint32_t addr) {
    HaltUnsupportedAccess("IOP13xx unsupported PMMR byte read", addr, 0);
}

void Iop13xxPmmrGuard::WriteWord(uint32_t addr, uint32_t value) {
    HaltUnsupportedAccess("IOP13xx unsupported PMMR word write", addr, value);
}

void Iop13xxPmmrGuard::WriteHalf(uint32_t addr, uint16_t value) {
    HaltUnsupportedAccess("IOP13xx unsupported PMMR halfword write", addr, value);
}

void Iop13xxPmmrGuard::WriteByte(uint32_t addr, uint8_t value) {
    HaltUnsupportedAccess("IOP13xx unsupported PMMR byte write", addr, value);
}
