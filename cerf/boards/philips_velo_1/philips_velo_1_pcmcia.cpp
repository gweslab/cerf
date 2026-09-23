#include "../../peripherals/ite_it8368/ite_it8368_socket_host.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/pcmcia/pcmcia_auto_insert.h"
#include "../../socs/pr31x00/pr31x00_ir.h"
#include "../board_context.h"
#include "philips_velo_1_id.h"

namespace {

/* CRDDET1 and CRDDET2 are the two card-detect pins of one 16-bit PC Card socket
   (it8368.c:419 treats either as "no card"), and only the Card 1 windows are ever
   mapped: nk.1.exe sub_9FB2B1E4 maps $6400_0000 and sub_9FB2B054 maps $0800_0000. */
class PhilipsVelo1Pcmcia : public IteIt8368SocketHost {
public:
    explicit PhilipsVelo1Pcmcia(CerfEmulator& emu)
        : IteIt8368SocketHost(emu, L"PC Card slot") {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
    }

    void OnReady() override {
        IteIt8368SocketHost::OnReady();
        emu_.Get<PcmciaAutoInsert>().InsertLaunchCompactFlash(Slot());
    }

    void OnIt8368IntLevel(bool asserted) override {
        emu_.Get<Pr31x00Ir>().DriveCarDetInput(asserted);
    }
};

}

REGISTER_SERVICE(PhilipsVelo1Pcmcia);
