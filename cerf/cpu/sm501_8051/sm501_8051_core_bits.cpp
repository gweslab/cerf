#include "sm501_8051_core.h"

namespace sm501_8051 {

/* Opcodes whose low nibble is 0 to 3, the CJNE family at B4h..BFh, and the
   MOVX forms at E2h, E3h, F2h and F3h.  Cycle counts are the oscillator
   periods of Table 10 divided by the twelve periods of one machine cycle. */
uint8_t Core::ExecuteBitAndJump(Bus& bus, uint8_t opcode) {
    const uint8_t high = static_cast<uint8_t>(opcode >> 4);
    const uint8_t low = static_cast<uint8_t>(opcode & 0x0Fu);

    /* Table 11: B4h and B5h compare the accumulator against an immediate or a
       direct byte, B6h and B7h indirect RAM against an immediate, and
       B8h..BFh a register against an immediate. */
    if (high == 0xBu && low >= 0x4u) {
        if (low == 0x4u) {
            const uint8_t immediate = Fetch(bus);
            CompareAndJump(bus, sfr_.Accumulator(), immediate);
        } else if (low == 0x5u) {
            const uint8_t value = sfr_.ReadDirect(Fetch(bus));
            CompareAndJump(bus, sfr_.Accumulator(), value);
        } else if (low == 0x6u || low == 0x7u) {
            const uint8_t value = sfr_.ReadIndirect(sfr_.Register(static_cast<uint8_t>(low - 0x6)));
            const uint8_t immediate = Fetch(bus);
            CompareAndJump(bus, value, immediate);
        } else {
            const uint8_t value = sfr_.Register(static_cast<uint8_t>(low - 0x8));
            const uint8_t immediate = Fetch(bus);
            CompareAndJump(bus, value, immediate);
        }
        return 2u;
    }

    switch (opcode) {
        case 0x00: return 1u;

        case 0x02: sfr_.SetPc(Fetch16(bus)); return 2u;
        case 0x12: {
            const uint16_t target = Fetch16(bus);
            Call(target);
            return 2u;
        }
        case 0x22:
        case 0x32: {
            const uint8_t high_byte = sfr_.Pop();
            const uint8_t low_byte = sfr_.Pop();
            sfr_.SetPc(static_cast<uint16_t>((high_byte << 8) | low_byte));
            if (opcode == 0x32u) sfr_.ReturnFromInterrupt();
            return 2u;
        }

        /* Table 11: 03h, 13h, 23h and 33h rotate the accumulator, the two odd
           forms through the carry. */
        case 0x03: {
            const uint8_t acc = sfr_.Accumulator();
            sfr_.SetAccumulator(static_cast<uint8_t>((acc >> 1) | (acc << 7)));
            return 1u;
        }
        case 0x13: {
            const uint8_t acc = sfr_.Accumulator();
            const bool carry = sfr_.Carry();
            sfr_.SetCarry((acc & 1u) != 0u);
            sfr_.SetAccumulator(static_cast<uint8_t>((acc >> 1) | (carry ? 0x80u : 0u)));
            return 1u;
        }
        case 0x23: {
            const uint8_t acc = sfr_.Accumulator();
            sfr_.SetAccumulator(static_cast<uint8_t>((acc << 1) | (acc >> 7)));
            return 1u;
        }
        case 0x33: {
            const uint8_t acc = sfr_.Accumulator();
            const bool carry = sfr_.Carry();
            sfr_.SetCarry((acc & 0x80u) != 0u);
            sfr_.SetAccumulator(static_cast<uint8_t>((acc << 1) | (carry ? 1u : 0u)));
            return 1u;
        }

        /* Table 11: 10h, 20h and 30h test a bit and branch; JBC also clears
           the bit it found set. */
        case 0x10: case 0x20: case 0x30: {
            const uint8_t bit_address = Fetch(bus);
            const bool bit = sfr_.ReadBit(bit_address);
            const bool taken = (opcode == 0x30u) ? !bit : bit;
            if (opcode == 0x10u && bit) sfr_.WriteBit(bit_address, false);
            Jump(bus, taken);
            return 2u;
        }

        case 0x40: Jump(bus, sfr_.Carry()); return 2u;
        case 0x50: Jump(bus, !sfr_.Carry()); return 2u;
        case 0x60: Jump(bus, sfr_.Accumulator() == 0u); return 2u;
        case 0x70: Jump(bus, sfr_.Accumulator() != 0u); return 2u;
        case 0x80: Jump(bus, true); return 2u;

        /* Table 11: 42h, 52h and 62h combine the accumulator into a direct
           byte, and 43h, 53h and 63h an immediate. */
        case 0x42: case 0x52: case 0x62:
        case 0x43: case 0x53: case 0x63: {
            const uint8_t address = Fetch(bus);
            const uint8_t operand = (low == 0x3u) ? Fetch(bus) : sfr_.Accumulator();
            const uint8_t current = sfr_.ReadDirect(address);
            uint8_t result = current;
            if (high == 0x4u) result = static_cast<uint8_t>(current | operand);
            if (high == 0x5u) result = static_cast<uint8_t>(current & operand);
            if (high == 0x6u) result = static_cast<uint8_t>(current ^ operand);
            sfr_.WriteDirect(address, result);
            return (low == 0x3u) ? 2u : 1u;
        }

        /* Table 11: 72h, 82h, A0h and B0h combine a bit, or its complement,
           into the carry. */
        case 0x72: case 0x82: case 0xA0: case 0xB0: {
            const uint8_t bit_address = Fetch(bus);
            bool bit = sfr_.ReadBit(bit_address);
            if (opcode == 0xA0u || opcode == 0xB0u) bit = !bit;
            const bool carry = sfr_.Carry();
            sfr_.SetCarry((opcode == 0x72u || opcode == 0xA0u) ? (carry || bit) : (carry && bit));
            return 2u;
        }

        case 0x73:
            sfr_.SetPc(static_cast<uint16_t>(sfr_.Dptr() + sfr_.Accumulator()));
            return 2u;

        /* Table 11: 83h and 93h read a code byte relative to the address that
           follows the instruction or to the data pointer. */
        case 0x83:
            sfr_.SetAccumulator(bus.FetchCode(static_cast<uint16_t>(sfr_.Pc() + sfr_.Accumulator())));
            return 2u;
        case 0x93:
            sfr_.SetAccumulator(bus.FetchCode(static_cast<uint16_t>(sfr_.Dptr() + sfr_.Accumulator())));
            return 2u;

        case 0x90: sfr_.SetDptr(Fetch16(bus)); return 2u;

        case 0x92: {
            const uint8_t bit_address = Fetch(bus);
            sfr_.WriteBit(bit_address, sfr_.Carry());
            return 2u;
        }
        case 0xA2:
            sfr_.SetCarry(sfr_.ReadBit(Fetch(bus)));
            return 1u;

        case 0xA3:
            sfr_.SetDptr(static_cast<uint16_t>(sfr_.Dptr() + 1u));
            return 2u;

        case 0xA4: {
            const uint16_t product =
                static_cast<uint16_t>(sfr_.Accumulator() * static_cast<uint16_t>(sfr_.B()));
            uint8_t psw = static_cast<uint8_t>(sfr_.Psw() & ~(kPswCarry | kPswOverflow));
            if (product > 0xFFu) psw |= kPswOverflow;
            sfr_.SetPsw(psw);
            sfr_.SetAccumulator(static_cast<uint8_t>(product));
            sfr_.SetB(static_cast<uint8_t>(product >> 8));
            return 4u;
        }

        case 0xB2:
        case 0xC2:
        case 0xD2: {
            const uint8_t bit_address = Fetch(bus);
            const bool value = (opcode == 0xD2u) ? true
                             : (opcode == 0xC2u) ? false
                                                 : !sfr_.ReadBit(bit_address);
            sfr_.WriteBit(bit_address, value);
            return 1u;
        }
        case 0xB3: sfr_.SetCarry(!sfr_.Carry()); return 1u;
        case 0xC3: sfr_.SetCarry(false); return 1u;
        case 0xD3: sfr_.SetCarry(true); return 1u;

        case 0xC0: sfr_.Push(sfr_.ReadDirect(Fetch(bus))); return 2u;
        case 0xD0: {
            const uint8_t address = Fetch(bus);
            sfr_.WriteDirect(address, sfr_.Pop());
            return 2u;
        }

        /* MCS-51 Programmer's Guide, MOVX: "In the second type of MOVX
           instruction, the Data Pointer generates a sixteen-bit address."  E0h
           and F0h are that type. */
        case 0xE0: sfr_.SetAccumulator(bus.ReadExternal(sfr_.Dptr())); return 2u;
        case 0xF0: bus.WriteExternal(sfr_.Dptr(), sfr_.Accumulator()); return 2u;

        /* MCS-51 Programmer's Guide, MOVX. */
        case 0xE2: case 0xE3:
            sfr_.SetAccumulator(
                bus.ReadExternal(sfr_.Register(static_cast<uint8_t>(opcode & 1u))));
            return 2u;
        case 0xF2: case 0xF3:
            bus.WriteExternal(sfr_.Register(static_cast<uint8_t>(opcode & 1u)),
                              sfr_.Accumulator());
            return 2u;

        default:
            break;
    }

    /* MCS-51 Programmer's Guide, Table 11. */
    Raise(bus, "unexpected opcode dispatch miss", opcode);
}

}  // namespace sm501_8051
