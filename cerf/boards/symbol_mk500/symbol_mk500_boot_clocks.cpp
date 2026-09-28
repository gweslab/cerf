#include "../../core/service.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "symbol_mk500_id.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/pxa27x/pxa27x_clock_manager.h"
#include "../../socs/pxa27x/pxa27x_power_manager.h"

#include <cstdint>

namespace {

/* symbol_mk500 flash.bin boot XIP nk.exe sub_80001958, called from start at
   0x80001310 on every reset: CKEN <- 0x400240 (0x8000196C), sub_80001CCC
   CKEN |= 0x8000, PCFR |= 0x40, PVCR <- 0 (0x80001CD0-0x80001CF8). */
constexpr uint32_t kCccrPa    = 0x41300000u;
constexpr uint32_t kCkenPa    = 0x41300004u;
constexpr uint32_t kPcfrPa    = 0x40F0001Cu;
constexpr uint32_t kPvcrPa    = 0x40F00040u;
constexpr uint32_t kPcmd0Pa   = 0x40F00080u;
constexpr uint32_t kBootCken  = 0x00408240u;

/* sub_80001D1C (R1 = 0xD): PCMD0 <- 0x430 | R1, PVCR <- 0xB0C, PCFR |= 0x400
   (0x80001D1C-0x80001D40); CCCR <- 0x290 (0x80001AA0); OSCC <- OON and a spin
   on OOK (0x80001AA4-0x80001AB4); CLKCFG <- 0xB (0x80001AD8). */
constexpr uint32_t kBootPcfrSet = 0x00000440u;
constexpr uint32_t kBootPvcr    = 0x00000B0Cu;
constexpr uint32_t kBootPcmd0   = 0x0000043Du;
constexpr uint32_t kBootCccr    = 0x00000290u;
constexpr uint32_t kBootClkcfg  = 0x0000000Bu;

class SymbolMk500BootClocks : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SymbolMk500;
    }

    void OnReady() override {
        Apply();
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] { Apply(); });
    }

private:
    void Apply() {
        auto& clocks = emu_.Get<Pxa27xClockManager>();
        clocks.WriteWord(kCkenPa, kBootCken);
        clocks.WriteWord(kCccrPa, kBootCccr);
        clocks.SetOscillatorStable();
        clocks.WriteClkcfg(kBootClkcfg);
        auto& pm = emu_.Get<Pxa27xPowerManager>();
        pm.WriteWord(kPcfrPa, pm.ReadWord(kPcfrPa) | kBootPcfrSet);
        pm.WriteWord(kPvcrPa, kBootPvcr);
        pm.WriteWord(kPcmd0Pa, kBootPcmd0);
    }
};

}

REGISTER_SERVICE(SymbolMk500BootClocks);
