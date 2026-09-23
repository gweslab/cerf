#include "../../peripherals/ite_it8368/ite_it8368_socket_host.h"

#include "../../core/cerf_emulator.h"
#include "../../socs/pr31x00/pr31x00_io.h"
#include "../board_context.h"
#include "philips_nino_300_id.h"

namespace {

constexpr uint32_t kIt8368IntMfioPin = 2;

class PhilipsNino300Pcmcia : public IteIt8368SocketHost {
public:
    explicit PhilipsNino300Pcmcia(CerfEmulator& emu)
        : IteIt8368SocketHost(emu, L"CompactFlash slot") {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsNino300;
    }

    void OnIt8368IntLevel(bool asserted) override {
        emu_.Get<Pr31x00Io>().DriveMfioInput(kIt8368IntMfioPin, asserted);
    }
};

}

REGISTER_SERVICE(PhilipsNino300Pcmcia);
