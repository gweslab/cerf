#include "open_bus_window.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "peripheral_dispatcher.h"

bool OpenBusWindow::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == WindowBoard();
}

void OpenBusWindow::OnReady() {
    const uint32_t page_size = 1u << kPageShift;
    noted_pages_.assign((MmioSize() + page_size - 1u) / page_size, false);
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t  OpenBusWindow::ReadByte(uint32_t addr) { Note("r8",  addr); return 0xFFu; }
uint16_t OpenBusWindow::ReadHalf(uint32_t addr) { Note("r16", addr); return 0xFFFFu; }
uint32_t OpenBusWindow::ReadWord(uint32_t addr) { Note("r32", addr); return 0xFFFFFFFFu; }

void OpenBusWindow::WriteByte(uint32_t addr, uint8_t)  { Note("w8",  addr); }
void OpenBusWindow::WriteHalf(uint32_t addr, uint16_t) { Note("w16", addr); }
void OpenBusWindow::WriteWord(uint32_t addr, uint32_t) { Note("w32", addr); }

void OpenBusWindow::Note(const char* op, uint32_t addr) {
    const size_t page = (addr - MmioBase()) >> kPageShift;
    if (page >= noted_pages_.size() || noted_pages_[page]) return;
    noted_pages_[page] = true;
    LOG(Periph, "[%s] %s 0x%08X (floating bus)\n", WindowName(), op, addr);
}
