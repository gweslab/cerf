#include "siemens_mp377_debug_led_peripheral.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_context.h"

bool SiemensMp377DebugLedPeripheral::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377DebugLedPeripheral::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t SiemensMp377DebugLedPeripheral::ReadByte(uint32_t addr) {
    HaltUnsupportedAccess("MP377 debug LED byte read", addr, 0);
}

uint16_t SiemensMp377DebugLedPeripheral::ReadHalf(uint32_t addr) {
    HaltUnsupportedAccess("MP377 debug LED halfword read", addr, 0);
}

uint32_t SiemensMp377DebugLedPeripheral::ReadWord(uint32_t addr) {
    HaltUnsupportedAccess("MP377 debug LED word read", addr, 0);
}

void SiemensMp377DebugLedPeripheral::WriteByte(uint32_t addr, uint8_t value) {
    HaltUnsupportedAccess("MP377 debug LED byte write", addr, value);
}

void SiemensMp377DebugLedPeripheral::WriteHalf(uint32_t addr, uint16_t value) {
    HaltUnsupportedAccess("MP377 debug LED halfword write", addr, value);
}

void SiemensMp377DebugLedPeripheral::WriteWord(uint32_t addr, uint32_t value) {
    HaltUnsupportedAccess("MP377 debug LED word write", addr, value);
}
