#include "ite_it8368_bus_window.h"

#include "ite_it8368.h"

#include "../peripheral_dispatcher.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"

void IteIt8368BusWindow::OnReady() { emu_.Get<PeripheralDispatcher>().Register(this); }

uint16_t IteIt8368BusWindow::ReadHalf(uint32_t addr) {
    const uint16_t v = emu_.Get<IteIt8368>().ReadReg(addr - MmioBase());
    return LanesCrossed() ? cerf::ByteSwap16(v) : v;
}

void IteIt8368BusWindow::WriteHalf(uint32_t addr, uint16_t value) {
    emu_.Get<IteIt8368>().WriteReg(addr - MmioBase(),
                                   LanesCrossed() ? cerf::ByteSwap16(value) : value);
}

void IteIt8368BusWindow::SaveState(StateWriter& w) { emu_.Get<IteIt8368>().SaveState(w); }

void IteIt8368BusWindow::RestoreState(StateReader& r) { emu_.Get<IteIt8368>().RestoreState(r); }
