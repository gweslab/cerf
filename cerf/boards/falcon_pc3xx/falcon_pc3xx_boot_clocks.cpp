#include "../../core/service.h"

#include "../../core/cerf_emulator.h"
#include "../board_context.h"
#include "falcon_4220_id.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/pxa255/pxa255_clock_manager.h"

#include <cstdint>

namespace {

/* falcon_4220__4_10 nk.exe sub_800B9524, called by the sleep-exit path sub_800BA740
   at 0x800BA7A8: CKEN <- 0, CCCR <- 0x241, OSCC <- OON and a spin until OOK
   (0x800B95F4-0x800B9608) unless MIDR[3:0] == 2, then MCR p14 c6 <- 3. */
constexpr uint32_t kCccrPa     = 0x41300000u;
constexpr uint32_t kCkenPa     = 0x41300004u;
constexpr uint32_t kBootCken   = 0x00000000u;
constexpr uint32_t kBootCccr   = 0x00000241u;
constexpr uint32_t kBootClkcfg = 0x00000003u;

class FalconPc3xxBootClocks : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Falcon4220;
    }

    void OnReady() override {
        Apply();
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] {
            if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) Apply();
        });
    }

private:
    void Apply() {
        auto& clocks = emu_.Get<Pxa255ClockManager>();
        clocks.WriteWord(kCkenPa, kBootCken);
        clocks.WriteWord(kCccrPa, kBootCccr);
        clocks.SetOscillatorStable();
        clocks.WriteClkcfg(kBootClkcfg);
    }
};

}

REGISTER_SERVICE(FalconPc3xxBootClocks);
