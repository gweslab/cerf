#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/pr31x00/pr31x00_intc.h"
#include "../board_context.h"
#include "sharp_mobilon_hc4100_id.h"

namespace {

/* HC-4100 nk.exe never sets INTC GLOBALEN - it RMW-preserves it (sub_91021678
   @0x910216C8 ori $t0,$t9,0x8000) and save/clears/restores it around Cmtt I/O
   (sub_910234FC @0x9102352C and $t9,$t8,0xFFFBFFFF). */
class SharpMobilonHc4100Bootloader : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SharpMobilonHc4100;
    }

    void OnReady() override {
        emu_.Get<Pr31x00Intc>().SetGlobalEnable();
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener(
            [this] { emu_.Get<Pr31x00Intc>().SetGlobalEnable(); });
    }
};

}  /* namespace */

REGISTER_SERVICE(SharpMobilonHc4100Bootloader);
