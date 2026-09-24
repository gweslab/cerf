#include "pr31x00_biu.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C00000u;

/* §4.7.1: Reserved<31> ENDCLKOUTTRI<30> DISDQMINIT<29> ENSDRAMPD<28> SHOWDINO<27>
   ENRMAP2<26> ENRMAP1<25> ENWRINPAGE<24> ENCS3USER<23> ENCS2USER<22> ENCS1USER<21>
   ENCS1DRAM<20> BANK1CONF<19:18> BANK0CONF<17:16> ROWSEL1<15:14> ROWSEL0<13:12>
   COLSEL1<11:8> COLSEL0<7:4> CS3SIZE<3> CS2SIZE<2> CS1SIZE<1> CS0SIZE<0>. */
constexpr uint32_t kCfg0Reserved  = 1u << 31;

/* DCLKOUT tri-state, the DQM power-down init sequence, SDRAM auto power-down, the
   external debug shadow of internal register accesses, and Address Re-Mapper 1 and 2,
   which would move the physical memory map. All reset to 0. */
constexpr uint32_t kCfg0Unmodeled = 0x7E000000u;

/* Setting ENCS1DRAM maps CS1 in place of DRAM BANK 0 and BANK 1 (§4.2.1), moving the
   DRAM the board backs. */
constexpr uint32_t kCfg0EnCs1Dram = 1u << 20;

/* §4.7.4: CARD2ACCVAL<31:28> CARD1ACCVAL<27:24> CARD2IOACCVAL<23:20>
   CARD1IOACCVAL<19:16> ENMCS3PAGE<15> ENMCS2PAGE<14> ENMCS1PAGE<13> ENMCS0PAGE<12>
   ENCS3PAGE<11> ENCS2PAGE<10> ENCS1PAGE<9> ENCS0PAGE<8> CARD2WAITEN<7> CARD1WAITEN<6>
   CARD2IOEN<5> CARD1IOEN<4> PORT8SEL<3> PORT2_8SEL<2> PORT1_8SEL<1> DCLKDISABLE<0>. */
constexpr uint32_t kCfg3Card2IoEn = 1u << 5;
constexpr uint32_t kCfg3Card1IoEn = 1u << 4;

/* DCLKDISABLE gates the DCLKOUT pin (§4.7.4); it resets to 0. */
constexpr uint32_t kCfg3DclkDisable = 1u << 0;

/* §4.7.5: ENBANK1HDRAM<31> ENBANK0HDRAM<30> ENARB<29> DISSNOOP<28> CLRWRBUSERRINT<27>
   ENBANK1OPT<26> ENBANK0OPT<25> ENWATCH<24> WATCHTIMEVAL<23:20> Reserved<19:17>
   MEMPOWERDOWN<16> ENRFSH1<15> ENRFSH0<14> RFSHVAL1<13:8> Reserved<7:6> RFSHVAL0<5:0>. */
constexpr uint32_t kCfg4Reserved = 0x000E00C0u;

/* ENARB and DISSNOOP control CPU-interface arbitration and the SNOOP signal during DMA;
   CLRWRBUSERRINT gates WRBUSERRINT, which drives CPU INT[0] directly and independently
   of the interrupt controller. */
constexpr uint32_t kCfg4Unmodeled = (1u << 29) | (1u << 28) | (1u << 27);

/* "The first access outside them clears the MEMPOWERDOWN bit and DRAMs and/or SDRAMs will
   go out of the self-refresh mode" (§12.2.7, p.12-10) - only cache and internal-function-
   register accesses hold it. CERF has no cache, so the guest's next access clears it. */
constexpr uint32_t kCfg4MemPowerDown = 1u << 16;

}  /* namespace */

bool Pr31x00Biu::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00Biu::OnReady() { emu_.Get<PeripheralDispatcher>().Register(this); }

bool Pr31x00Biu::Card1IoSpace() const { return (reg_[3] & kCfg3Card1IoEn) != 0; }
bool Pr31x00Biu::Card2IoSpace() const { return (reg_[3] & kCfg3Card2IoEn) != 0; }

uint32_t Pr31x00Biu::ReadWord(uint32_t addr) {
    const uint32_t idx = (addr - kBase) / 4u;
    if (idx >= kRegs) HaltUnsupportedAccess("PR31x00 BIU ReadWord", addr, 0);
    return reg_[idx];
}

void Pr31x00Biu::WriteWord(uint32_t addr, uint32_t value) {
    switch ((addr - kBase) / 4u) {
        case 0: WriteConfig0(addr, value); return;

        /* MEM_CONFIG1 (§4.7.2) is eight MCSnACCVALn access times and MEM_CONFIG2
           (§4.7.3) is eight CSnACCVALn access times, in bus clocks; CERF completes
           every access in zero wait states. */
        case 1: reg_[1] = value; return;
        case 2: reg_[2] = value; return;

        case 3: WriteConfig3(addr, value); return;
        case 4: WriteConfig4(addr, value); return;

        default: HaltUnsupportedAccess("PR31x00 BIU WriteWord", addr, value);
    }
}

void Pr31x00Biu::WriteConfig0(uint32_t addr, uint32_t value) {
    if (value & kCfg0Reserved) {
        HaltUnsupportedAccess("PR31x00 BIU MEM_CONFIG0 reserved", addr, value);
    }
    if (value & kCfg0Unmodeled) {
        HaltUnsupportedAccess("PR31x00 BIU MEM_CONFIG0 unmodeled control", addr, value);
    }
    if (value & kCfg0EnCs1Dram) {
        HaltUnsupportedAccess("PR31x00 BIU MEM_CONFIG0 ENCS1DRAM", addr, value);
    }
    /* BANKnCONF / ROWSELn / COLSELn place address bits on the multiplexed DRAM pins
       and CSnSIZE picks a 16- or 32-bit port (§4.7.1); ENWRINPAGE holds DRAM page
       mode, ENCSnUSER expose CS1-CS3 in kuseg. CERF's DRAM is a flat host buffer
       with no address multiplexing, and its decode is identical in kuseg. */
    reg_[0] = value;
}

void Pr31x00Biu::WriteConfig3(uint32_t addr, uint32_t value) {
    if (value & kCfg3DclkDisable) {
        HaltUnsupportedAccess("PR31x00 BIU MEM_CONFIG3 DCLKDISABLE", addr, value);
    }
    /* §4.7.4: PORT8SEL / PORTn_8SEL select the 8- or 16-bit PCMCIA port size,
       CARDnACCVAL / CARDnIOACCVAL are access times, ENMCSnPAGE / ENCSnPAGE the
       read-page-mode enables, CARDnWAITEN the wait-signal enables. */
    reg_[3] = value;
}

void Pr31x00Biu::WriteConfig4(uint32_t addr, uint32_t value) {
    if (value & kCfg4Reserved) {
        HaltUnsupportedAccess("PR31x00 BIU MEM_CONFIG4 reserved", addr, value);
    }
    if (value & kCfg4Unmodeled) {
        HaltUnsupportedAccess("PR31x00 BIU MEM_CONFIG4 unmodeled control", addr, value);
    }
    /* Device type, RAS-to-CAS, refresh interval and the bus Watch Dog Timer (§4.7.5).
       CERF's host-backed DRAM neither refreshes nor loses contents. */
    reg_[4] = value & ~kCfg4MemPowerDown;
}

void Pr31x00Biu::SaveState(StateWriter& w) {
    for (uint32_t i = 0; i < kRegs; ++i) w.Write("reg", reg_[i]);
}

void Pr31x00Biu::RestoreState(StateReader& r) {
    for (uint32_t i = 0; i < kRegs; ++i) r.Read("reg", reg_[i]);
}

REGISTER_SERVICE(Pr31x00Biu);
