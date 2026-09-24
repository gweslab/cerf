#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../board_context.h"
#include "nec_mobilepro_700_id.h"

#include <cstdint>

namespace {

/* MobilePro 700 OAL host-link parallel port (nk.exe OEMParallelPortSendByte
   sub_9F003460 / GetByte sub_9F003388). No docked host under CERF, so the peer
   handshake never completes and the guest's send/recv time out. */
class NecMobilePro700ParallelPort : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro700;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return 0x20u; }

    uint8_t ReadByte(uint32_t addr) override {
        switch (addr - kBase) {
            case kStatusOff:  return PeerStatus();
            case kDataInOff:  return PeerRxByte();
            case kCommandOff: return command_;
            default: break;
        }
        HaltUnsupportedAccess("MobilePro700 ParallelPort ReadByte", addr, 0);
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        switch (addr - kBase) {
            case kProbeOff:   return;   /* presence probe; must decode apart from COM SCR 0xFFCE. */
            case kDataOutOff:
                LOG(Board, "MobilePro700 parallel-port TX 0x%02X (no docked peer)\n", value);
                return;
            case kStatusOff:  return;   /* control write; no peer to drive, never read back. */
            case kCommandOff: command_ = value; return;
            default: break;
        }
        HaltUnsupportedAccess("MobilePro700 ParallelPort WriteByte", addr, value);
    }

    void SaveState(StateWriter& w) override { w.Write("command", command_); }
    void RestoreState(StateReader& r) override { r.Read("command", command_); }

private:
    static constexpr uint32_t kBase       = 0x1600FFE0u;
    static constexpr uint32_t kProbeOff   = 0x0Eu;   /* 0xFFEE */
    static constexpr uint32_t kDataOutOff = 0x10u;   /* 0xFFF0 */
    static constexpr uint32_t kDataInOff  = 0x12u;   /* 0xFFF2 */
    static constexpr uint32_t kStatusOff  = 0x14u;   /* 0xFFF4 */
    static constexpr uint32_t kCommandOff = 0x16u;   /* 0xFFF6 */

    uint8_t PeerStatus() const { return 0u; }   /* D1/D4 deasserted - no docked peer. */
    uint8_t PeerRxByte() const { return 0u; }

    uint8_t command_ = 0u;
};

}  /* namespace */

REGISTER_SERVICE(NecMobilePro700ParallelPort);
