#include "../host_request_channel.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "mips_interrupt_channel.h"

namespace {

class MipsHostRequestChannel : public HostRequestChannel {
public:
    using HostRequestChannel::HostRequestChannel;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips;
    }

protected:
    void Kick() override {
        emu_.Get<MipsInterruptChannel>().RequestDispatch(MipsInterruptChannel::kDispatchHostClock);
    }
};

}

REGISTER_SERVICE_AS(MipsHostRequestChannel, HostRequestChannel);
