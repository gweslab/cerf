#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "msm8255_dal_remote_server.h"
#include "msm8255_modem_peer.h"
#include "msm8255_rpc_router_peer.h"
#include "msm8255_rpc_server.h"
#include "msm8255_rpc_server_registry.h"

#include <atomic>
#include <cstdint>

namespace {

/* Linux arch/arm/mach-msm msm_iomap-7x30.h:
   MSM_GCC_PHYS 0xC0182000, MSM_GCC_SIZE SZ_4K. */
constexpr uint32_t kGccBase = 0xC0182000u;
constexpr uint32_t kGccSize = 0x00001000u;

constexpr uint32_t kReg04         = 0x04u;
constexpr uint32_t kReg04Accepted = 0x3FFu;
constexpr uint32_t kReg04Reset    = 0u;

/* Linux arch/arm/mach-msm smd_private.h msm_a2m_int writes 1 << irq to
   MSM_GCC_BASE + 0x8. */
constexpr uint32_t kRegA2mInt = 0x08u;

class Msm8255Gcc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            reg04_.store(kReg04Reset, std::memory_order_release);
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kGccBase; }
    uint32_t MmioSize() const override { return kGccSize; }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == kRegA2mInt) {
            emu_.Get<Msm8255ModemPeer>().RingDoorbell(value);
            return;
        }
        if (off != kReg04 || value != kReg04Accepted) {
            HaltUnsupportedAccess("WriteWord", addr, value);
        }
        reg04_.store(value, std::memory_order_release);
    }

    void SaveState(StateWriter& w) override {
        w.Write<uint32_t>("reg04", reg04_.load(std::memory_order_acquire));
        emu_.Get<Msm8255RpcRouterPeer>().SaveState(w);
        for (auto* server : emu_.Get<Msm8255RpcServerRegistry>().Servers()) {
            server->SaveState(w);
        }
        emu_.Get<Msm8255DalRemoteServer>().SaveState(w);
    }

    void RestoreState(StateReader& r) override {
        uint32_t reg04 = 0;
        r.Read("reg04", reg04);
        if (reg04 != kReg04Reset && reg04 != kReg04Accepted) {
            r.Reject(
                "msm8255 gcc: restored +0x04 value 0x%08X was never written "
                "by the guest", reg04);
        }
        reg04_.store(reg04, std::memory_order_release);
        emu_.Get<Msm8255RpcRouterPeer>().RestoreState(r);
        for (auto* server : emu_.Get<Msm8255RpcServerRegistry>().Servers()) {
            server->RestoreState(r);
        }
        emu_.Get<Msm8255DalRemoteServer>().RestoreState(r);
    }

private:
    std::atomic<uint32_t> reg04_{kReg04Reset};
};

}

REGISTER_SERVICE(Msm8255Gcc);
