#include "sm501_8051_core.h"

namespace sm501_8051 {

[[noreturn]] void Raise(Bus& bus, const char* what, uint32_t detail) {
    bus.Fault(what, detail);
    __assume(0);
}

uint16_t Core::Fetch16(Bus& bus) {
    const uint8_t high = Fetch(bus);
    const uint8_t low = Fetch(bus);
    return static_cast<uint16_t>((high << 8) | low);
}

uint8_t Core::ReadOperand(Bus& bus, uint8_t low_nibble) {
    switch (low_nibble) {
        case 0x4: return Fetch(bus);
        case 0x5: return sfr_.ReadDirect(Fetch(bus));
        case 0x6: return sfr_.ReadIndirect(sfr_.Register(0));
        case 0x7: return sfr_.ReadIndirect(sfr_.Register(1));
        default: return sfr_.Register(static_cast<uint8_t>(low_nibble - 0x8));
    }
}

/* MCS-51 Programmer's Guide, ADD: CY is set on a carry out of bit 7, AC on a
   carry out of bit 3, and OV when the carry into bit 7 differs from the carry
   out of it. */
void Core::Add(uint8_t value, bool with_carry) {
    const uint8_t acc = sfr_.Accumulator();
    const uint8_t carry_in = (with_carry && sfr_.Carry()) ? 1u : 0u;
    const uint16_t sum = static_cast<uint16_t>(acc + value + carry_in);
    const uint8_t result = static_cast<uint8_t>(sum);

    uint8_t psw = static_cast<uint8_t>(sfr_.Psw() & ~(kPswCarry | kPswAuxCarry | kPswOverflow));
    if (sum > 0xFFu) psw |= kPswCarry;
    if (((acc & 0x0Fu) + (value & 0x0Fu) + carry_in) > 0x0Fu) psw |= kPswAuxCarry;
    if ((((acc ^ result) & (value ^ result)) & 0x80u) != 0u) psw |= kPswOverflow;
    sfr_.SetPsw(psw);
    sfr_.SetAccumulator(result);
}

/* MCS-51 Programmer's Guide, SUBB: the borrow enters through CY, and OV is set
   when a borrow is needed into bit 7 but not out of it, or the other way. */
void Core::Subtract(uint8_t value) {
    const uint8_t acc = sfr_.Accumulator();
    const uint8_t borrow = sfr_.Carry() ? 1u : 0u;
    const uint16_t difference = static_cast<uint16_t>(acc - value - borrow);
    const uint8_t result = static_cast<uint8_t>(difference);

    uint8_t psw = static_cast<uint8_t>(sfr_.Psw() & ~(kPswCarry | kPswAuxCarry | kPswOverflow));
    if (static_cast<uint16_t>(value) + borrow > acc) psw |= kPswCarry;
    if ((value & 0x0Fu) + borrow > (acc & 0x0Fu)) psw |= kPswAuxCarry;
    if ((((acc ^ value) & (acc ^ result)) & 0x80u) != 0u) psw |= kPswOverflow;
    sfr_.SetPsw(psw);
    sfr_.SetAccumulator(result);
}

void Core::Jump(Bus& bus, bool taken) {
    const int8_t offset = static_cast<int8_t>(Fetch(bus));
    if (taken) sfr_.SetPc(static_cast<uint16_t>(sfr_.Pc() + offset));
}

void Core::CompareAndJump(Bus& bus, uint8_t lhs, uint8_t rhs) {
    Jump(bus, lhs != rhs);
    sfr_.SetCarry(lhs < rhs);
}

void Core::Call(uint16_t target) {
    const uint16_t ret = sfr_.Pc();
    sfr_.Push(static_cast<uint8_t>(ret));
    sfr_.Push(static_cast<uint8_t>(ret >> 8));
    sfr_.SetPc(target);
}

/* Table 11, AJMP and ACALL: the eleven-bit destination is built from bits 7:5
   of the opcode and the following byte, inside the 2 KB page of the address
   that follows the instruction. */
uint16_t Core::AbsoluteTarget(uint8_t opcode, uint8_t low) {
    const uint16_t page = static_cast<uint16_t>(sfr_.Pc() & 0xF800u);
    const uint16_t high = static_cast<uint16_t>((opcode & 0xE0u) << 3);
    return static_cast<uint16_t>(page | high | low);
}

uint8_t Core::Step(Bus& bus) {
    sfr_.SetBus(&bus);
    if (!sfr_.TakeVectorBlock() && sfr_.ServiceInterrupts()) {
        /* MCS-51 Hardware Description, Response Time: "The call itself takes
           two cycles." */
        return 2u;
    }
    const uint8_t opcode = Fetch(bus);
    const uint8_t cycles = Execute(bus, opcode);
    sfr_.CountInstruction();
    return cycles;
}

uint8_t Core::Execute(Bus& bus, uint8_t opcode) {
    const uint8_t high = static_cast<uint8_t>(opcode >> 4);
    const uint8_t low = static_cast<uint8_t>(opcode & 0x0Fu);

    /* Table 11: AJMP occupies x1 for even high nibbles and ACALL x1 for odd
       ones, across the whole map. */
    if (low == 0x1u) {
        const uint8_t operand = Fetch(bus);
        const uint16_t target = AbsoluteTarget(opcode, operand);
        if ((opcode & 0x10u) == 0u) {
            sfr_.SetPc(target);
        } else {
            Call(target);
        }
        return 2u;
    }

    if (low >= 0x4u) {
        switch (high) {
            case 0x0: case 0x1: case 0x2: case 0x3:
            case 0x4: case 0x5: case 0x6: case 0x9:
                return ExecuteArithmetic(bus, opcode);
            case 0x7: case 0x8: case 0xA: case 0xC:
            case 0xD: case 0xE: case 0xF:
                return ExecuteMove(bus, opcode);
            case 0xB:
                return ExecuteBitAndJump(bus, opcode);
            default:
                break;
        }
    }
    return ExecuteBitAndJump(bus, opcode);
}

uint8_t Core::ExecuteArithmetic(Bus& bus, uint8_t opcode) {
    const uint8_t high = static_cast<uint8_t>(opcode >> 4);
    const uint8_t low = static_cast<uint8_t>(opcode & 0x0Fu);

    /* Table 11: 04h..0Fh increment and 14h..1Fh decrement, with 4 naming the
       accumulator, 5 a direct byte, 6 and 7 indirect RAM and 8 to F the
       registers. */
    if (high == 0x0u || high == 0x1u) {
        const bool increment = high == 0x0u;
        const int8_t delta = increment ? 1 : -1;
        switch (low) {
            case 0x4:
                sfr_.SetAccumulator(static_cast<uint8_t>(sfr_.Accumulator() + delta));
                return 1u;
            case 0x5: {
                const uint8_t address = Fetch(bus);
                sfr_.WriteDirect(address, static_cast<uint8_t>(sfr_.ReadDirect(address) + delta));
                return 1u;
            }
            case 0x6: case 0x7: {
                const uint8_t address = sfr_.Register(static_cast<uint8_t>(low - 0x6));
                sfr_.WriteIndirect(address, static_cast<uint8_t>(sfr_.ReadIndirect(address) + delta));
                return 1u;
            }
            default: {
                const uint8_t index = static_cast<uint8_t>(low - 0x8);
                sfr_.SetRegister(index, static_cast<uint8_t>(sfr_.Register(index) + delta));
                return 1u;
            }
        }
    }

    const uint8_t operand = ReadOperand(bus, low);
    switch (high) {
        case 0x2: Add(operand, false); break;
        case 0x3: Add(operand, true); break;
        case 0x4: sfr_.SetAccumulator(static_cast<uint8_t>(sfr_.Accumulator() | operand)); break;
        case 0x5: sfr_.SetAccumulator(static_cast<uint8_t>(sfr_.Accumulator() & operand)); break;
        case 0x6: sfr_.SetAccumulator(static_cast<uint8_t>(sfr_.Accumulator() ^ operand)); break;
        case 0x9: Subtract(operand); break;
        default: Raise(bus, "unexpected arithmetic dispatch opcode", opcode);
    }
    /* Table 10 gives every form of these families twelve oscillator periods,
       which is one machine cycle. */
    return 1u;
}

uint8_t Core::ExecuteMove(Bus& bus, uint8_t opcode) {
    const uint8_t high = static_cast<uint8_t>(opcode >> 4);
    const uint8_t low = static_cast<uint8_t>(opcode & 0x0Fu);

    switch (high) {
        /* Table 11: 74h..7Fh load an immediate byte into the accumulator, a
           direct byte, indirect RAM or a register. */
        case 0x7:
            switch (low) {
                case 0x4: sfr_.SetAccumulator(Fetch(bus)); return 1u;
                case 0x5: {
                    const uint8_t address = Fetch(bus);
                    sfr_.WriteDirect(address, Fetch(bus));
                    return 2u;
                }
                case 0x6: case 0x7:
                    sfr_.WriteIndirect(sfr_.Register(static_cast<uint8_t>(low - 0x6)), Fetch(bus));
                    return 1u;
                default:
                    sfr_.SetRegister(static_cast<uint8_t>(low - 0x8), Fetch(bus));
                    return 1u;
            }

        /* Table 11: 85h moves a direct byte to a direct byte, 86h and 87h
           indirect RAM to a direct byte, and 88h..8Fh a register to one. */
        case 0x8: {
            if (low == 0x4u) {
                /* 84h DIV AB: A takes the quotient, B the remainder, CY is
                   cleared and OV set when B is zero. */
                const uint8_t divisor = sfr_.B();
                uint8_t psw = static_cast<uint8_t>(sfr_.Psw() & ~(kPswCarry | kPswOverflow));
                if (divisor == 0u) {
                    psw |= kPswOverflow;
                    sfr_.SetPsw(psw);
                } else {
                    const uint8_t dividend = sfr_.Accumulator();
                    sfr_.SetPsw(psw);
                    sfr_.SetAccumulator(static_cast<uint8_t>(dividend / divisor));
                    sfr_.SetB(static_cast<uint8_t>(dividend % divisor));
                }
                return 4u;
            }
            if (low == 0x5u) {
                const uint8_t source = Fetch(bus);
                const uint8_t destination = Fetch(bus);
                sfr_.WriteDirect(destination, sfr_.ReadDirect(source));
                return 2u;
            }
            const uint8_t value = (low == 0x6u || low == 0x7u)
                                      ? sfr_.ReadIndirect(sfr_.Register(static_cast<uint8_t>(low - 0x6)))
                                      : sfr_.Register(static_cast<uint8_t>(low - 0x8));
            sfr_.WriteDirect(Fetch(bus), value);
            return 2u;
        }

        /* Table 11: A6h and A7h move a direct byte into indirect RAM, and
           A8h..AFh into a register. */
        case 0xA: {
            /* Table 11: A4h multiplies and A5h is the one reserved code. */
            if (low == 0x4u) return ExecuteBitAndJump(bus, opcode);
            if (low == 0x5u) Raise(bus, "reserved opcode A5h", opcode);
            const uint8_t address = Fetch(bus);
            const uint8_t value = sfr_.ReadDirect(address);
            if (low == 0x6u || low == 0x7u) {
                sfr_.WriteIndirect(sfr_.Register(static_cast<uint8_t>(low - 0x6)), value);
            } else {
                sfr_.SetRegister(static_cast<uint8_t>(low - 0x8), value);
            }
            return 2u;
        }

        /* Table 11: C4h swaps the accumulator nibbles and C5h..CFh exchange it
           with a direct byte, indirect RAM or a register. */
        case 0xC: {
            if (low == 0x4u) {
                const uint8_t acc = sfr_.Accumulator();
                sfr_.SetAccumulator(static_cast<uint8_t>((acc >> 4) | (acc << 4)));
                return 1u;
            }
            const uint8_t acc = sfr_.Accumulator();
            if (low == 0x5u) {
                const uint8_t address = Fetch(bus);
                const uint8_t value = sfr_.ReadDirect(address);
                sfr_.WriteDirect(address, acc);
                sfr_.SetAccumulator(value);
                return 1u;
            }
            if (low == 0x6u || low == 0x7u) {
                const uint8_t address = sfr_.Register(static_cast<uint8_t>(low - 0x6));
                const uint8_t value = sfr_.ReadIndirect(address);
                sfr_.WriteIndirect(address, acc);
                sfr_.SetAccumulator(value);
                return 1u;
            }
            const uint8_t index = static_cast<uint8_t>(low - 0x8);
            const uint8_t value = sfr_.Register(index);
            sfr_.SetRegister(index, acc);
            sfr_.SetAccumulator(value);
            return 1u;
        }

        /* Table 11: D5h decrements a direct byte and jumps while it is not
           zero, D6h and D7h exchange the low nibbles with indirect RAM, and
           D8h..DFh decrement a register and jump. */
        case 0xD: {
            if (low == 0x4u) {
                /* D4h DA A: the decimal adjust adds six to a nibble that
                   exceeds nine or produced a carry out of it. */
                uint8_t acc = sfr_.Accumulator();
                bool carry = sfr_.Carry();
                if ((acc & 0x0Fu) > 9u || (sfr_.Psw() & kPswAuxCarry) != 0u) {
                    const uint16_t sum = static_cast<uint16_t>(acc + 6u);
                    if (sum > 0xFFu) carry = true;
                    acc = static_cast<uint8_t>(sum);
                }
                if ((acc & 0xF0u) > 0x90u || carry) {
                    const uint16_t sum = static_cast<uint16_t>(acc + 0x60u);
                    if (sum > 0xFFu) carry = true;
                    acc = static_cast<uint8_t>(sum);
                }
                sfr_.SetAccumulator(acc);
                sfr_.SetCarry(carry);
                return 1u;
            }
            if (low == 0x5u) {
                const uint8_t address = Fetch(bus);
                const uint8_t value = static_cast<uint8_t>(sfr_.ReadDirect(address) - 1u);
                sfr_.WriteDirect(address, value);
                Jump(bus, value != 0u);
                return 2u;
            }
            if (low == 0x6u || low == 0x7u) {
                const uint8_t address = sfr_.Register(static_cast<uint8_t>(low - 0x6));
                const uint8_t value = sfr_.ReadIndirect(address);
                const uint8_t acc = sfr_.Accumulator();
                sfr_.WriteIndirect(address, static_cast<uint8_t>((value & 0xF0u) | (acc & 0x0Fu)));
                sfr_.SetAccumulator(static_cast<uint8_t>((acc & 0xF0u) | (value & 0x0Fu)));
                return 1u;
            }
            const uint8_t index = static_cast<uint8_t>(low - 0x8);
            const uint8_t value = static_cast<uint8_t>(sfr_.Register(index) - 1u);
            sfr_.SetRegister(index, value);
            Jump(bus, value != 0u);
            return 2u;
        }

        /* Table 11: E4h clears the accumulator and E5h..EFh load it. */
        case 0xE:
            if (low == 0x4u) {
                sfr_.SetAccumulator(0u);
                return 1u;
            }
            sfr_.SetAccumulator(ReadOperand(bus, low));
            return 1u;

        /* Table 11: F4h complements the accumulator and F5h..FFh store it. */
        case 0xF: {
            if (low == 0x4u) {
                sfr_.SetAccumulator(static_cast<uint8_t>(~sfr_.Accumulator()));
                return 1u;
            }
            const uint8_t acc = sfr_.Accumulator();
            if (low == 0x5u) {
                sfr_.WriteDirect(Fetch(bus), acc);
                return 1u;
            }
            if (low == 0x6u || low == 0x7u) {
                sfr_.WriteIndirect(sfr_.Register(static_cast<uint8_t>(low - 0x6)), acc);
                return 1u;
            }
            sfr_.SetRegister(static_cast<uint8_t>(low - 0x8), acc);
            return 1u;
        }

        default:
            break;
    }
    Raise(bus, "unexpected move dispatch opcode", opcode);
}

}  // namespace sm501_8051
