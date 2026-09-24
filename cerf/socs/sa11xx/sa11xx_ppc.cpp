#include "sa11xx_ppc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

/* SA-1110 Dev Man §11.13.3 PPDR - 0=input, 1=output, reset all-0 (all input).
   §11.13.4 PPSR - 22 pin-state bits; an output pin reads its PPC-controlled
   value, an input pin reads the external pin level; PPSR is not reset,
   reserved bits 31:22 read 0. */

bool Sa11xxPpc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 ||
                  bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxPpc::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa11xxPpc::DriveInputPin(uint32_t pin, bool level) {
    if (pin >= 22u) return;
    std::lock_guard<std::mutex> lk(mtx_);
    if (level) input_state_ |=  (1u << pin);
    else       input_state_ &= ~(1u << pin);
}

uint8_t Sa11xxPpc::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t index;
    if (OffsetToIndex(base, &index)) {
        std::lock_guard<std::mutex> lk(mtx_);
        const uint32_t word = (index == kPpsrIndex) ? ReadPpsrLocked()
                                                    : regs_[index];
        return static_cast<uint8_t>((word >> shift) & 0xFFu);
    }
    if (base == kMccr1Offset)
        return static_cast<uint8_t>((mccr1_ >> shift) & 0xFFu);
    if (base == kReservedIrdaPoke) {
        LOG(Periph, "[Sa11xxPpc] reserved read +0x%02X -> 0\n", off);
        return 0;
    }
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

uint32_t Sa11xxPpc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t index;
    if (OffsetToIndex(off, &index)) {
        std::lock_guard<std::mutex> lk(mtx_);
        return (index == kPpsrIndex) ? ReadPpsrLocked() : regs_[index];
    }
    if (off == kMccr1Offset) return mccr1_;
    if (off == kReservedIrdaPoke) {
        LOG(Periph, "[Sa11xxPpc] reserved read +0x%02X -> 0\n", off);
        return 0;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa11xxPpc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t index;
    if (OffsetToIndex(base, &index)) {
        std::lock_guard<std::mutex> lk(mtx_);
        const uint32_t cleared = regs_[index] & ~(0xFFu << shift);
        regs_[index] = cleared | (static_cast<uint32_t>(value) << shift);
        return;
    }
    if (base == kMccr1Offset) {
        const uint32_t cleared = mccr1_ & ~(0xFFu << shift);
        mccr1_ = cleared | (static_cast<uint32_t>(value) << shift);
        return;
    }
    if (base == kReservedIrdaPoke) {
        LOG(Periph, "[Sa11xxPpc] reserved write +0x%02X (ignored)\n", base);
        return;
    }
    HaltUnsupportedAccess("WriteByte", addr, value);
}

void Sa11xxPpc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t index;
    if (OffsetToIndex(off, &index)) {
        std::lock_guard<std::mutex> lk(mtx_);
        regs_[index] = value;
        return;
    }
    if (off == kMccr1Offset) { mccr1_ = value; return; }
    if (off == kReservedIrdaPoke) {
        LOG(Periph, "[Sa11xxPpc] reserved write +0x%02X = 0x%08X (ignored)\n", off, value);
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Sa11xxPpc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.WriteBytes("regs", regs_, sizeof(regs_));
    w.Write("input_state", input_state_);
    w.Write("mccr1", mccr1_);
}

void Sa11xxPpc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.ReadBytes("regs", regs_, sizeof(regs_));
    r.Read("input_state", input_state_);
    r.Read("mccr1", mccr1_);
}

REGISTER_SERVICE(Sa11xxPpc);
