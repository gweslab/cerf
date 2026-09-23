#include "../../peripherals/ite_it8368/ite_it8368_socket_host.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/pr31x00/pr31x00_io.h"
#include "../board_context.h"
#include "sharp_mobilon_hc4100_id.h"

namespace {

/* The IT8368E INT pin reaches multi-function I/O pin 2: the nk.exe OAL interrupt
   dispatch table at unk_91002338 maps Interrupt Status 3 bit 2 to SYSINTR $10,
   which pcmcia.dll sub_1492478 registers through InterruptInitialize. */
constexpr uint32_t kIt8368IntMfioPin = 2;

class SharpMobilonHc4100Pcmcia : public IteIt8368SocketHost {
public:
    explicit SharpMobilonHc4100Pcmcia(CerfEmulator& emu)
        : IteIt8368SocketHost(emu, L"PC Card slot") {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SharpMobilonHc4100;
    }

    void OnIt8368IntLevel(bool asserted) override {
        emu_.Get<Pr31x00Io>().DriveMfioInput(kIt8368IntMfioPin, asserted);
    }
};

}

REGISTER_SERVICE(SharpMobilonHc4100Pcmcia);
