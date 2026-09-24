#include "nec_mobilepro_900_board_window.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "nec_mobilepro_900_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool NecMobilePro900BoardWindow::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
}

void NecMobilePro900BoardWindow::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t NecMobilePro900BoardWindow::ReadByte(uint32_t addr) {
    const uint32_t shift = (addr & 0x3u) * 8;
    return static_cast<uint8_t>((ReadReg(addr & ~0x3u) >> shift) & 0xFFu);
}

uint16_t NecMobilePro900BoardWindow::ReadHalf(uint32_t addr) {
    const uint32_t shift = (addr & 0x2u) * 8;
    return static_cast<uint16_t>((ReadReg(addr & ~0x3u) >> shift) & 0xFFFFu);
}

uint32_t NecMobilePro900BoardWindow::ReadWord(uint32_t addr) { return ReadReg(addr); }

void NecMobilePro900BoardWindow::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = (addr - MmioBase()) & ~0x3u;
    const uint32_t shift = (addr & 0x3u) * 8;
    uint32_t w = regs_.count(off) ? regs_[off] : 0u;
    w = (w & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift);
    regs_[off] = w;
    LOG(Caution, "NecBoardWindow[%s]: WriteByte PA 0x%08X (off 0x%X) = 0x%02X "
                 "(unmodeled, needs per-driver RE)\n",
        WindowName(), addr, off, value);
}

void NecMobilePro900BoardWindow::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off   = (addr - MmioBase()) & ~0x3u;
    const uint32_t shift = (addr & 0x2u) * 8;
    uint32_t w = regs_.count(off) ? regs_[off] : 0u;
    w = (w & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(value) << shift);
    regs_[off] = w;
    LOG(Caution, "NecBoardWindow[%s]: WriteHalf PA 0x%08X (off 0x%X) = 0x%04X "
                 "(unmodeled, needs per-driver RE)\n",
        WindowName(), addr, off, value);
}

void NecMobilePro900BoardWindow::WriteWord(uint32_t addr, uint32_t value) {
    regs_[addr - MmioBase()] = value;
    LOG(Caution, "NecBoardWindow[%s]: WriteWord PA 0x%08X (off 0x%X) = 0x%08X "
                 "(unmodeled, needs per-driver RE)\n",
        WindowName(), addr, addr - MmioBase(), value);
}

uint32_t NecMobilePro900BoardWindow::ReadReg(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    auto it = regs_.find(off);
    const uint32_t v = (it != regs_.end()) ? it->second : 0u;
    LOG(Caution, "NecBoardWindow[%s]: read PA 0x%08X (off 0x%X) -> 0x%08X "
                 "(unmodeled, needs per-driver RE)\n",
        WindowName(), addr, off, v);
    return v;
}

void NecMobilePro900BoardWindow::SaveState(StateWriter& w) {
    w.Write("regs_count", static_cast<uint32_t>(regs_.size()));
    for (const auto& [off, val] : regs_) { w.Write("off", off); w.Write("val", val); }
}

void NecMobilePro900BoardWindow::RestoreState(StateReader& r) {
    regs_.clear();
    uint32_t n = 0;
    r.Read("regs_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t off = 0, val = 0;
        r.Read("off", off);
        r.Read("val", val);
        regs_[off] = val;
    }
}
