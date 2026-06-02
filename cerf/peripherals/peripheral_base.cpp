#include "peripheral_base.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../jit/arm_cpu_ops.h"
#include "../jit/arm_jit.h"
#include "../jit/cpu_state.h"

#include <typeinfo>

uint8_t  Peripheral::ReadByte (uint32_t addr) { HaltUnsupportedAccess("ReadByte",  addr, 0); }
uint16_t Peripheral::ReadHalf (uint32_t addr) { HaltUnsupportedAccess("ReadHalf",  addr, 0); }
uint32_t Peripheral::ReadWord (uint32_t addr) { HaltUnsupportedAccess("ReadWord",  addr, 0); }
uint64_t Peripheral::ReadDword(uint32_t addr) { HaltUnsupportedAccess("ReadDword", addr, 0); }
void Peripheral::WriteByte (uint32_t addr, uint8_t  value) { HaltUnsupportedAccess("WriteByte",  addr, value); }
void Peripheral::WriteHalf (uint32_t addr, uint16_t value) { HaltUnsupportedAccess("WriteHalf",  addr, value); }
void Peripheral::WriteWord (uint32_t addr, uint32_t value) { HaltUnsupportedAccess("WriteWord",  addr, value); }
void Peripheral::WriteDword(uint32_t addr, uint64_t value) { HaltUnsupportedAccess("WriteDword", addr, value); }

uint32_t Peripheral::AutoFastRead(void* ctx, uint32_t off, uint32_t width) {
    auto* p = static_cast<Peripheral*>(ctx);
    const uint32_t addr = p->MmioBase() + off;
    switch (width) {
        case 1: return p->ReadByte(addr);
        case 2: return p->ReadHalf(addr);
        case 4: return p->ReadWord(addr);
    }
    p->HaltUnsupportedAccess("AutoFastRead", addr, width);
}

void Peripheral::AutoFastWrite(void* ctx, uint32_t off, uint32_t value, uint32_t width) {
    auto* p = static_cast<Peripheral*>(ctx);
    const uint32_t addr = p->MmioBase() + off;
    switch (width) {
        case 1: p->WriteByte(addr, static_cast<uint8_t> (value)); return;
        case 2: p->WriteHalf(addr, static_cast<uint16_t>(value)); return;
        case 4: p->WriteWord(addr, value); return;
    }
    p->HaltUnsupportedAccess("AutoFastWrite", addr, value);
}

void Peripheral::HaltUnsupportedAccess(const char* op,
                                       uint32_t addr,
                                       uint64_t value) const {
    LOG(Caution, "Peripheral '%s' rejected %s at 0x%08X (value 0x%016llX)\n",
            typeid(*this).name(), op, addr,
            static_cast<unsigned long long>(value));
    /* Dump JIT register state at fault time so the rejecting call site
       is visible in the log. Mirrors Mmu::RaiseAbort's diagnostic dump.
       Same pattern: every peripheral halt is a FATAL, register state at
       the halt is always useful to the next investigator. */
    auto* state      = emu_.Get<ArmJit>().CpuState();
    const auto& r    = state->gprs;
    const uint32_t c = ArmCpuGetCpsrWithFlags(state);
    LOG(Caution, "      guest PC=0x%08X CPSR=0x%08X\n", r[15], c);
    LOG(Caution, "      R0=0x%08X  R1=0x%08X  R2=0x%08X  R3=0x%08X "
                 "R4=0x%08X  R5=0x%08X  R6=0x%08X  R7=0x%08X\n",
        r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    LOG(Caution, "      R8=0x%08X  R9=0x%08X  R10=0x%08X R11=0x%08X "
                 "R12=0x%08X SP=0x%08X  LR=0x%08X\n",
        r[8], r[9], r[10], r[11], r[12], r[13], r[14]);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}
