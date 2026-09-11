#define NOMINMAX

#include "siemens_mp377_smi_bridge.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/irq_controller.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace siemens_mp377 {

bool SiemensMp377SmiBridge::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377SmiBridge::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) Reset();
    });
}

void SiemensMp377SmiBridge::Reset() {
    master_pending_.store(0u, std::memory_order_release);
    bridge_status_.store(0u, std::memory_order_release);
    bridge_enable_.store(0xFFFFFFFFu, std::memory_order_release);
    DeassertCascade();
}

uint32_t SiemensMp377SmiBridge::Sm501MasterStatus() const {
    return master_pending_.load(std::memory_order_acquire) ? kSm501MasterBit : 0u;
}

/* siemens_mp377_v1040 nk.exe OAL IRQ dispatch table[24]=0x80443B78;
   sub_80445A70, bridge VA 0x81AAF7EC, SYSINTR 46. */
void SiemensMp377SmiBridge::AssertCascade() {
    emu_.Get<IrqController>().AssertIrq(kCascadeSource);
}

void SiemensMp377SmiBridge::DeassertCascade() {
    emu_.Get<IrqController>().DeAssertIrq(kCascadeSource);
}

void SiemensMp377SmiBridge::AssertPending() {
    master_pending_.store(1u, std::memory_order_release);
    bridge_status_.fetch_or(kBridgeStatusBit, std::memory_order_acq_rel);
    AssertCascade();
}

void SiemensMp377SmiBridge::ClearPending() {
    master_pending_.store(0u, std::memory_order_release);
    bridge_status_.store(0u, std::memory_order_release);
    DeassertCascade();
}

uint32_t SiemensMp377SmiBridge::Read(uint32_t pa) const {
    switch ((pa & ~3u) & 0x0Fu) {
    case 0x04u: {
        const uint32_t value = bridge_enable_.load(std::memory_order_acquire);
        return value;
    }
    case 0x08u: {
        const uint32_t value = bridge_status_.load(std::memory_order_acquire);
        return value;
    }
    default:
        emu_.Get<Fatal>().Die("MP377 SMI bridge unsupported read at 0x%08X", pa);
    }
}

void SiemensMp377SmiBridge::Write(uint32_t pa, uint32_t value) {
    switch ((pa & ~3u) & 0x0Fu) {
    case 0x04u:
        bridge_enable_.store(value, std::memory_order_release);
        break;
    case 0x08u:
        bridge_status_.store(value & kBridgeValidStatusBits, std::memory_order_release);
        if ((value & kBridgeValidStatusBits) == 0u) ClearPending();
        break;
    default:
        emu_.Get<Fatal>().Die("MP377 SMI bridge unsupported write at 0x%08X = 0x%08X",
                              pa, value);
    }
}

void SiemensMp377SmiBridge::SaveState(StateWriter& w) const {
    uint32_t v = master_pending_.load(std::memory_order_acquire);
    w.Write(v);
    v = bridge_status_.load(std::memory_order_acquire);
    w.Write(v);
    v = bridge_enable_.load(std::memory_order_acquire);
    w.Write(v);
}

void SiemensMp377SmiBridge::RestoreState(StateReader& r) {
    uint32_t master = 0;
    uint32_t status = 0;
    uint32_t enable = 0xFFFFFFFFu;
    r.Read(master);
    r.Read(status);
    r.Read(enable);
    master_pending_.store(master ? 1u : 0u, std::memory_order_release);
    bridge_status_.store(status & kBridgeValidStatusBits, std::memory_order_release);
    bridge_enable_.store(enable, std::memory_order_release);
}

void SiemensMp377SmiBridge::PostRestoreState() {
    if (master_pending_.load(std::memory_order_acquire) ||
        (bridge_status_.load(std::memory_order_acquire) & kBridgeStatusBit) != 0u) {
        AssertCascade();
    } else {
        DeassertCascade();
    }
}

REGISTER_SERVICE(SiemensMp377SmiBridge);

} // namespace siemens_mp377
