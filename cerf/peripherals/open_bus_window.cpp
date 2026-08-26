#include "open_bus_window.h"

#include "../core/cerf_emulator.h"
#include "peripheral_dispatcher.h"

bool OpenBusWindow::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == WindowBoard();
}

void OpenBusWindow::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t  OpenBusWindow::ReadByte (uint32_t) { return 0xFFu; }
uint16_t OpenBusWindow::ReadHalf (uint32_t) { return 0xFFFFu; }
uint32_t OpenBusWindow::ReadWord (uint32_t) { return 0xFFFFFFFFu; }
uint64_t OpenBusWindow::ReadDword(uint32_t) { return 0xFFFFFFFFFFFFFFFFull; }

void OpenBusWindow::WriteByte (uint32_t, uint8_t)  {}
void OpenBusWindow::WriteHalf (uint32_t, uint16_t) {}
void OpenBusWindow::WriteWord (uint32_t, uint32_t) {}
void OpenBusWindow::WriteDword(uint32_t, uint64_t) {}
