#include "sa1111_unit.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../peripheral_dispatcher.h"
#include "sa1111_reset_line.h"
#include "sa1111_sbi.h"

#include <typeinfo>

void Sa1111Unit::OnReady() {
    auto& line  = emu_.Get<Sa1111ResetLine>();
    reset_line_ = &line;
    rclk_gated_ = ClockedByRclk();
    if (rclk_gated_) sbi_ = &emu_.Get<Sa1111Sbi>();
    OnUnitReady();
    emu_.Get<PeripheralDispatcher>().Register(this);
    line.RegisterListener([this](bool held) { OnChipReset(held); });
}

bool Sa1111Unit::ChipHeld() const { return reset_line_->Held(); }
bool Sa1111Unit::ChipHoldPending() const { return reset_line_->PowerOnHoldPending(); }

/* SA-1111 Developer's Manual §2.4.2: "RCLK must be turned on for any register accesses to
   functional blocks beyond the SBI (System Bus Interface). SBI registers, on the other
   hand, are latch-based and can be written without RCLK enabled." §2.4: "Sleep-All clocks
   are disabled". */
void Sa1111Unit::RequireAccessible(uint32_t addr) {
    reset_line_->SettleRelease();
    reset_line_->RequireReleased(typeid(*this).name(), addr);
    if (!rclk_gated_) return;
    if (!sbi_->BusClocksEnabled() || sbi_->SleepRequested()) {
        emu_.Get<Fatal>().Die("%s: access at 0x%08X with SKCR RCLKEn clear or Sleep set is not "
                              "modelled", typeid(*this).name(), addr);
    }
    if (reset_line_->Held()) {
        emu_.Get<Fatal>().Die("%s: access at 0x%08X with nBRES asserted is not modelled",
                              typeid(*this).name(), addr);
    }
    if (sbi_->ClockDisturbed()) {
        emu_.Get<Fatal>().Die("%s: access at 0x%08X after the SA-1111 CLK input changed outside "
                              "reset is not modelled", typeid(*this).name(), addr);
    }
}

uint8_t  Sa1111Unit::ReadByte (uint32_t addr) { RequireAccessible(addr); return UnitReadByte(addr); }
uint16_t Sa1111Unit::ReadHalf (uint32_t addr) { RequireAccessible(addr); return UnitReadHalf(addr); }
uint32_t Sa1111Unit::ReadWord (uint32_t addr) { RequireAccessible(addr); return UnitReadWord(addr); }
uint64_t Sa1111Unit::ReadDword(uint32_t addr) { RequireAccessible(addr); return UnitReadDword(addr); }
void Sa1111Unit::WriteByte (uint32_t addr, uint8_t  value) { RequireAccessible(addr); UnitWriteByte(addr, value); }
void Sa1111Unit::WriteHalf (uint32_t addr, uint16_t value) { RequireAccessible(addr); UnitWriteHalf(addr, value); }
void Sa1111Unit::WriteWord (uint32_t addr, uint32_t value) { RequireAccessible(addr); UnitWriteWord(addr, value); }
void Sa1111Unit::WriteDword(uint32_t addr, uint64_t value) { RequireAccessible(addr); UnitWriteDword(addr, value); }

Peripheral::FastReadFn  Sa1111Unit::FastReader() { return Peripheral::FastReader(); }
Peripheral::FastWriteFn Sa1111Unit::FastWriter() { return Peripheral::FastWriter(); }

uint8_t  Sa1111Unit::UnitReadByte (uint32_t addr) { HaltUnsupportedAccess("ReadByte",  addr, 0); }
uint16_t Sa1111Unit::UnitReadHalf (uint32_t addr) { HaltUnsupportedAccess("ReadHalf",  addr, 0); }
uint32_t Sa1111Unit::UnitReadWord (uint32_t addr) { HaltUnsupportedAccess("ReadWord",  addr, 0); }
uint64_t Sa1111Unit::UnitReadDword(uint32_t addr) { HaltUnsupportedAccess("ReadDword", addr, 0); }
void Sa1111Unit::UnitWriteByte (uint32_t addr, uint8_t  value) { HaltUnsupportedAccess("WriteByte",  addr, value); }
void Sa1111Unit::UnitWriteHalf (uint32_t addr, uint16_t value) { HaltUnsupportedAccess("WriteHalf",  addr, value); }
void Sa1111Unit::UnitWriteWord (uint32_t addr, uint32_t value) { HaltUnsupportedAccess("WriteWord",  addr, value); }
void Sa1111Unit::UnitWriteDword(uint32_t addr, uint64_t value) { HaltUnsupportedAccess("WriteDword", addr, value); }
