#pragma once

#include "sm501_8051_state.h"

#include "../../state/state_stream.h"

namespace sm501_8051 {

class Bus;

class Sfr {
public:
    void Reset();
    void SetBus(Bus* bus) { bus_ = bus; }

    void SaveState(StateWriter& writer) const;
    void RestoreState(StateReader& reader);

    uint8_t ReadDirect(uint8_t address) const;
    void WriteDirect(uint8_t address, uint8_t value);
    uint8_t ReadIndirect(uint8_t address) const { return state_.iram[address]; }
    void WriteIndirect(uint8_t address, uint8_t value) { state_.iram[address] = value; }

    bool ReadBit(uint8_t bit_address) const;
    void WriteBit(uint8_t bit_address, bool value);

    uint8_t Register(uint8_t index) const { return state_.iram[BankBase() + index]; }
    void SetRegister(uint8_t index, uint8_t value) { state_.iram[BankBase() + index] = value; }

    uint8_t Accumulator() const { return state_.acc; }
    void SetAccumulator(uint8_t value);
    uint8_t B() const { return state_.b; }
    void SetB(uint8_t value) { state_.b = value; }
    uint8_t Psw() const { return state_.psw; }
    void SetPsw(uint8_t value);
    bool Carry() const { return (state_.psw & kPswCarry) != 0u; }
    void SetCarry(bool value);

    uint16_t Dptr() const { return static_cast<uint16_t>((state_.dph << 8) | state_.dpl); }
    void SetDptr(uint16_t value);

    void Push(uint8_t value);
    uint8_t Pop();

    uint16_t Pc() const { return state_.pc; }
    void SetPc(uint16_t value) { state_.pc = value; }
    uint16_t TakePcByte() { return state_.pc++; }

    uint64_t Executed() const { return state_.executed; }
    void CountInstruction() { ++state_.executed; }

    void SignalExtended(uint8_t line) {
        state_.extended_pending |= static_cast<uint8_t>(1u << line);
    }

    bool ServiceInterrupts();
    void ReturnFromInterrupt();
    bool HighPriorityInterruptInService() const {
        return (state_.in_service & kInServiceHigh) != 0u;
    }

    bool TakeVectorBlock();

private:
    uint8_t BankBase() const {
        return static_cast<uint8_t>(((state_.psw & (kPswRs1 | kPswRs0)) >> 3) * 8u);
    }
    void RefreshParity();
    void EnterVector(uint16_t vector, bool high_priority);
    bool CanTakeLevel(bool high_priority) const;

    Bus* bus_ = nullptr;
    State state_;
};

}  // namespace sm501_8051
