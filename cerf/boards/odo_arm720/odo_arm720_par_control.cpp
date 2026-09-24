#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <mutex>

namespace {


constexpr uint32_t kParControlPaBase = 0x04020000u;
constexpr uint32_t kParControlSize   = 0x04u;

constexpr uint32_t kParEn          = 0x80000000u;
constexpr uint32_t kParAutoEn      = 0x20000000u;
constexpr uint32_t kParBusy        = 0x10000000u;
constexpr uint32_t kParNack        = 0x08000000u;
constexpr uint32_t kParSelect      = 0x02000000u;
constexpr uint32_t kParNfault      = 0x01000000u;
constexpr uint32_t kParIntr        = 0x00100000u;
constexpr uint32_t kParAutoFd      = 0x00020000u;
constexpr uint32_t kParDataIn      = 0x0000FF00u;

/* Peer-driven bits - read returns the peer's view regardless of
   what the kernel last wrote into these positions. */
constexpr uint32_t kPeerDrivenMask = kParAutoFd | kParIntr | kParDataIn;

constexpr uint32_t kPeerByte = 0xFFu;

class OdoArm720ParControl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(Board, "Odo PAR_CONTROL_REG: virtual parallel-port peer "
                "attached at PA 0x04020000. The peer answers the byte "
                "handshake on AUTOFD and always presents 0xFF on "
                "PAR_DATA_IN.\n");
    }

    uint32_t MmioBase() const override { return kParControlPaBase; }
    uint32_t MmioSize() const override { return kParControlSize; }

    /* State image: the last kernel-written control word plus the
       derived peer AUTOFD level, which together reproduce the next
       ReadWord overlay exactly. */
    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write<uint32_t>("kernel_wrote", kernel_wrote_);
        w.Write<bool>("peer_autofd_high", peer_autofd_high_);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("kernel_wrote", kernel_wrote_);
        r.Read("peer_autofd_high", peer_autofd_high_);
    }

    uint32_t ReadWord(uint32_t addr) override {
        if (addr != MmioBase()) HaltUnsupportedAccess("ReadWord", addr, 0);
        uint32_t value;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            /* Start from kernel-written control bits, overlay the
               peer-driven input bits per the current peer state. */
            value = kernel_wrote_ & ~kPeerDrivenMask;
            if (peer_autofd_high_) value |= kParAutoFd;
            value |= kParIntr;                       /* always has byte */
            value |= (kPeerByte << 8) & kParDataIn;  /* byte = 0xFF */
        }
#if CERF_DEV_MODE
        LOG(Board, "Odo PAR_CONTROL read32 -> 0x%08X\n", value);
#endif
        return value;
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        if (addr != MmioBase()) HaltUnsupportedAccess("WriteWord", addr, value);
#if CERF_DEV_MODE
        LOG(Board, "Odo PAR_CONTROL write32 = 0x%08X\n", value);
#endif
        std::lock_guard<std::mutex> lk(state_mutex_);
        kernel_wrote_      = value;
        peer_autofd_high_  = ComputePeerAutoFdLocked(value);
    }

private:
    static bool ComputePeerAutoFdLocked(uint32_t kernel_value) {
        if (kernel_value & kParNack) {
            /* Step 4 of SendByte: kernel asserts NACK → peer
               signals "byte received" → AUTOFD low. */
            return false;
        }
        const uint32_t send_ready_mask = kParBusy | kParNfault | kParSelect;
        if ((kernel_value & send_ready_mask) == send_ready_mask
            && !(kernel_value & kParAutoEn)) {
            /* Steps 1 + 3 of SendByte: kernel writes
               BUSY+NFAULT+SELECT (with or without PAR_EN, but
               not AUTOEN) → peer signals "ready to receive" →
               AUTOFD high. */
            return true;
        }
        /* Receive-mode write (BUSY+NFAULT+AUTOEN+SELECT, or
           GetByte ack BUSY+AUTOEN+SELECT, or idle 0) → no
           transfer in progress → AUTOFD low. */
        return false;
    }

    mutable std::mutex state_mutex_;
    uint32_t           kernel_wrote_      = 0;
    bool               peer_autofd_high_  = false;
};

}  /* namespace */

REGISTER_SERVICE(OdoArm720ParControl);
