#include "open_bus_window.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "peripheral_dispatcher.h"

bool OpenBusWindow::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == WindowBoard();
}

void OpenBusWindow::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void OpenBusWindow::Trace(const char* op, uint32_t addr) {
    LOG(Periph, "[%s] %s 0x%08X (floating bus)\n", WindowTag(), op, addr);
}

uint8_t  OpenBusWindow::ReadByte (uint32_t addr) { Trace("r8",  addr); return 0xFFu; }
uint16_t OpenBusWindow::ReadHalf (uint32_t addr) { Trace("r16", addr); return 0xFFFFu; }
uint32_t OpenBusWindow::ReadWord (uint32_t addr) { Trace("r32", addr); return 0xFFFFFFFFu; }

void OpenBusWindow::WriteByte (uint32_t addr, uint8_t)  { Trace("w8",  addr); }
void OpenBusWindow::WriteHalf (uint32_t addr, uint16_t) { Trace("w16", addr); }
void OpenBusWindow::WriteWord (uint32_t addr, uint32_t) { Trace("w32", addr); }
