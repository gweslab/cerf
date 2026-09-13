#pragma once

#include "sm501_8051_sfr.h"

#include <cstdint>

namespace sm501_8051 {

/* MCS-51 Programmer's Guide, "Program and Data Memory": the code space is
   separate from the external data space that MOVX reaches. */
class Bus {
public:
    virtual ~Bus() = default;
    virtual uint8_t FetchCode(uint16_t address) const = 0;
    virtual uint8_t ReadExternal(uint16_t address) = 0;
    virtual void WriteExternal(uint16_t address, uint8_t value) = 0;

    [[noreturn]] virtual void Fault(const char* what, uint32_t detail) = 0;
};

[[noreturn]] void Raise(Bus& bus, const char* what, uint32_t detail);

class Core {
public:
    void Reset() { sfr_.Reset(); }

    uint8_t Step(Bus& bus);

    uint16_t ProgramCounter() const { return sfr_.Pc(); }
    uint64_t Executed() const { return sfr_.Executed(); }
    bool HighPriorityInterruptInService() const { return sfr_.HighPriorityInterruptInService(); }

    /* siemens_mp377_v1040 SM501 8051 firmware: CODE:0030/0033/003B/0043,
       handlers CODE:08AF..0A80 and CODE:0E9D..0EEF, XDATA 900Ch. */
    void SignalProtocolInterrupt() { sfr_.SignalExtended(1u); }
    void SignalAc97Interrupt() { sfr_.SignalExtended(2u); }

    void SaveState(StateWriter& writer) const { sfr_.SaveState(writer); }
    void RestoreState(StateReader& reader) { sfr_.RestoreState(reader); }

private:
    uint8_t Fetch(Bus& bus) { return bus.FetchCode(sfr_.TakePcByte()); }
    uint16_t Fetch16(Bus& bus);

    /* Table 11 gives the same operand order to every arithmetic and logical
       family: low nibble 4 is immediate, 5 direct, 6 and 7 indirect through R0
       and R1, and 8 to F the eight registers of the selected bank. */
    uint8_t ReadOperand(Bus& bus, uint8_t low_nibble);

    void Add(uint8_t value, bool with_carry);
    void Subtract(uint8_t value);
    void Jump(Bus& bus, bool taken);
    void CompareAndJump(Bus& bus, uint8_t lhs, uint8_t rhs);
    void Call(uint16_t target);
    uint16_t AbsoluteTarget(uint8_t opcode, uint8_t low);

    uint8_t Execute(Bus& bus, uint8_t opcode);
    uint8_t ExecuteArithmetic(Bus& bus, uint8_t opcode);
    uint8_t ExecuteMove(Bus& bus, uint8_t opcode);
    uint8_t ExecuteBitAndJump(Bus& bus, uint8_t opcode);

    Sfr sfr_;
};

}  // namespace sm501_8051
