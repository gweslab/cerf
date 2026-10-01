#include "../host_request_channel.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "arm_interrupt_channel.h"

namespace {

class ArmHostRequestChannel : public HostRequestChannel {
public:
    using HostRequestChannel::HostRequestChannel;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
    }

protected:
    void Kick() override { emu_.Get<ArmInterruptChannel>().RequestHostService(); }
};

}

REGISTER_SERVICE_AS(ArmHostRequestChannel, HostRequestChannel);
