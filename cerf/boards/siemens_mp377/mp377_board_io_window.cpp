#include "mp377_board_io_window.h"

namespace mp377_board_io_detail {

bool Mp377BoardIoWindow::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SiemensMP377;
}

void Mp377BoardIoWindow::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t Mp377BoardIoWindow::ReadByte(uint32_t addr) {
    HaltUnsupportedAccess("MP377 unsupported board byte read", addr, 0);
}

uint16_t Mp377BoardIoWindow::ReadHalf(uint32_t addr) {
    HaltUnsupportedAccess("MP377 unsupported board halfword read", addr, 0);
}

uint32_t Mp377BoardIoWindow::ReadWord(uint32_t addr) {
    HaltUnsupportedAccess("MP377 unsupported board word read", addr, 0);
}

void Mp377BoardIoWindow::WriteByte(uint32_t addr, uint8_t value) {
    HaltUnsupportedAccess("MP377 unsupported board byte write", addr, value);
}

void Mp377BoardIoWindow::WriteHalf(uint32_t addr, uint16_t value) {
    HaltUnsupportedAccess("MP377 unsupported board halfword write", addr, value);
}

void Mp377BoardIoWindow::WriteWord(uint32_t addr, uint32_t value) {
    HaltUnsupportedAccess("MP377 unsupported board word write", addr, value);
}

} // namespace mp377_board_io_detail
