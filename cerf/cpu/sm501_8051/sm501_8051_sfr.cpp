#include "sm501_8051_core.h"

namespace sm501_8051 {

void Sfr::Reset() {
    state_ = State{};
}

/* MCS-51 Programmer's Guide, PSW.0; siemens_mp377_v1040 SM501 firmware
   CODE:08B5 and CODE:0A78. */
void Sfr::RefreshParity() {
    uint8_t parity = state_.acc;
    parity = static_cast<uint8_t>(parity ^ (parity >> 4));
    parity = static_cast<uint8_t>(parity ^ (parity >> 2));
    parity = static_cast<uint8_t>(parity ^ (parity >> 1));
    state_.psw = static_cast<uint8_t>((state_.psw & ~kPswParity) | (parity & 1u));
}

void Sfr::SetAccumulator(uint8_t value) {
    state_.acc = value;
    RefreshParity();
}

void Sfr::SetPsw(uint8_t value) {
    state_.psw = value;
    RefreshParity();
}

void Sfr::SetCarry(bool value) {
    state_.psw = value ? static_cast<uint8_t>(state_.psw | kPswCarry)
                       : static_cast<uint8_t>(state_.psw & ~kPswCarry);
}

void Sfr::SetDptr(uint16_t value) {
    state_.dpl = static_cast<uint8_t>(value);
    state_.dph = static_cast<uint8_t>(value >> 8);
}

void Sfr::Push(uint8_t value) {
    state_.sp = static_cast<uint8_t>(state_.sp + 1u);
    state_.iram[state_.sp] = value;
}

uint8_t Sfr::Pop() {
    const uint8_t value = state_.iram[state_.sp];
    state_.sp = static_cast<uint8_t>(state_.sp - 1u);
    return value;
}

uint8_t Sfr::ReadDirect(uint8_t address) const {
    if (address < 0x80u) return state_.iram[address];
    switch (address) {
        case kSfrSp: return state_.sp;
        case kSfrDpl: return state_.dpl;
        case kSfrDph: return state_.dph;
        case kSfrIe: return state_.ie;
        case kSfrPsw: return state_.psw;
        case kSfrAcc: return state_.acc;
        case kSfrB: return state_.b;
        case kSfrEie: return state_.eie;
        case kSfrEip: return state_.eip;
        default: break;
    }
    Raise(*bus_, "read of unmodelled special function register", address);
}

void Sfr::WriteDirect(uint8_t address, uint8_t value) {
    if (address < 0x80u) {
        state_.iram[address] = value;
        return;
    }
    switch (address) {
        case kSfrSp: state_.sp = value; return;
        case kSfrDpl: state_.dpl = value; return;
        case kSfrDph: state_.dph = value; return;
        case kSfrIe:
            state_.ie = value;
            state_.block_next_vector = true;
            return;
        case kSfrPsw: SetPsw(value); return;
        case kSfrAcc: SetAccumulator(value); return;
        case kSfrB: state_.b = value; return;
        case kSfrEie: state_.eie = value; return;
        case kSfrEip: state_.eip = value; return;
        default: break;
    }
    Raise(*bus_, "write of unmodelled special function register", address);
}

/* MCS-51 Programmer's Guide, Figure 5: bit addresses 00h..7Fh cover the
   bit-addressable RAM at 20h..2Fh, and 80h..FFh the bit-addressable SFRs,
   whose byte address is the bit address with the low three bits cleared. */
bool Sfr::ReadBit(uint8_t bit_address) const {
    const uint8_t byte_address = bit_address < 0x80u
                                     ? static_cast<uint8_t>(0x20u + (bit_address >> 3))
                                     : static_cast<uint8_t>(bit_address & 0xF8u);
    return ((ReadDirect(byte_address) >> (bit_address & 7u)) & 1u) != 0u;
}

void Sfr::WriteBit(uint8_t bit_address, bool value) {
    const uint8_t byte_address = bit_address < 0x80u
                                     ? static_cast<uint8_t>(0x20u + (bit_address >> 3))
                                     : static_cast<uint8_t>(bit_address & 0xF8u);
    const uint8_t mask = static_cast<uint8_t>(1u << (bit_address & 7u));
    uint8_t byte = ReadDirect(byte_address);
    byte = value ? static_cast<uint8_t>(byte | mask) : static_cast<uint8_t>(byte & ~mask);
    WriteDirect(byte_address, byte);
}

/* MCS-51 Hardware Description, How Interrupts Are Handled: "The hardware-
   generated LCALL pushes the contents of the Program Counter onto the stack
   (but it does not save the PSW)". */
void Sfr::EnterVector(uint16_t vector, bool high_priority) {
    Push(static_cast<uint8_t>(state_.pc));
    Push(static_cast<uint8_t>(state_.pc >> 8));
    state_.pc = vector;
    state_.in_service |= high_priority ? kInServiceHigh : kInServiceLow;
}

/* MCS-51 Hardware Description, How Interrupts Are Handled, condition 1. */
bool Sfr::CanTakeLevel(bool high_priority) const {
    return high_priority ? (state_.in_service & kInServiceHigh) == 0u
                         : state_.in_service == 0u;
}

bool Sfr::TakeVectorBlock() {
    const bool blocked = state_.block_next_vector;
    state_.block_next_vector = false;
    return blocked;
}

/* MCS-51 Hardware Description, Interrupt Enables/Priorities;
   siemens_mp377_v1040 SM501 firmware CODE:0030/0033/0036. */
bool Sfr::ServiceInterrupts() {
    if ((state_.ie & kIeGlobal) == 0u) return false;
    if ((state_.extended_pending & state_.eie) == 0u) return false;

    for (uint8_t pass = 0u; pass < 2u; ++pass) {
        const bool want_high = pass == 0u;
        if (!CanTakeLevel(want_high)) continue;

        for (uint8_t line = 0u; line < 8u; ++line) {
            const uint8_t mask = static_cast<uint8_t>(1u << line);
            if ((state_.extended_pending & mask) == 0u) continue;
            if ((state_.eie & mask) == 0u) continue;
            if (((state_.eip & mask) != 0u) != want_high) continue;
            state_.extended_pending = static_cast<uint8_t>(state_.extended_pending & ~mask);
            EnterVector(static_cast<uint16_t>(kVectorExtendedBase + kVectorStride * line),
                        want_high);
            return true;
        }
    }
    return false;
}

/* MCS-51 Hardware Description, How Interrupts Are Handled, condition 3. */
void Sfr::ReturnFromInterrupt() {
    if ((state_.in_service & kInServiceHigh) != 0u) {
        state_.in_service = static_cast<uint8_t>(state_.in_service & ~kInServiceHigh);
    } else {
        state_.in_service = static_cast<uint8_t>(state_.in_service & ~kInServiceLow);
    }
    state_.block_next_vector = true;
}

void Sfr::SaveState(StateWriter& writer) const {
    writer.Write(state_.pc);
    writer.WriteBytes(state_.iram.data(), state_.iram.size());
    writer.Write(state_.acc);
    writer.Write(state_.b);
    writer.Write(state_.psw);
    writer.Write(state_.sp);
    writer.Write(state_.dpl);
    writer.Write(state_.dph);
    writer.Write(state_.ie);
    writer.Write(state_.eie);
    writer.Write(state_.eip);
    writer.Write(state_.extended_pending);
    writer.Write(state_.in_service);
    writer.Write(state_.block_next_vector);
    writer.Write(state_.executed);
}

void Sfr::RestoreState(StateReader& reader) {
    reader.Read(state_.pc);
    reader.ReadBytes(state_.iram.data(), state_.iram.size());
    reader.Read(state_.acc);
    reader.Read(state_.b);
    reader.Read(state_.psw);
    reader.Read(state_.sp);
    reader.Read(state_.dpl);
    reader.Read(state_.dph);
    reader.Read(state_.ie);
    reader.Read(state_.eie);
    reader.Read(state_.eip);
    reader.Read(state_.extended_pending);
    reader.Read(state_.in_service);
    reader.Read(state_.block_next_vector);
    reader.Read(state_.executed);
}

}  // namespace sm501_8051
