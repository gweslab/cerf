#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <mutex>

namespace {

/* PPFS virtual peer — always-reply-0xFF makes kernel read_header
   (PPFS.C:143-150) fail the 0xAA5555AA sentinel and bail in µs
   instead of MDPPFS.C:78-132 spinning ~60s waiting for AUTOFD.
   Removing the AUTOFD-toggle state machine restores the spin. */

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

/* Peer-driven bits — read returns the peer's view regardless of
   what the kernel last wrote into these positions. */
constexpr uint32_t kPeerDrivenMask = kParAutoFd | kParIntr | kParDataIn;

/* The byte value the virtual peer always presents on PAR_DATA_IN.
   0xFF chosen so PPFS.C read_header (line 146) reads 0xFFFFFFFF
   as the four-byte sentinel value, failing the 0xAA5555AA check
   immediately. */
constexpr uint32_t kPeerByte = 0xFFu;

class OdoArm720ParControl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(Board, "Odo PAR_CONTROL_REG: virtual PPFS peer attached at "
                "PA 0x04020000. Peer follows byte handshake (MDPPFS.C "
                "78-132), always replies 0xFF at protocol layer. PPFS "
                "requests return -1 fast (sentinel check fails in "
                "PPFS.C read_header line 146); kernel falls back to "
                "ROM lookup.\n");
    }

    uint32_t MmioBase() const override { return kParControlPaBase; }
    uint32_t MmioSize() const override { return kParControlSize; }

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
    /* Map kernel's control-bit write pattern to the peer's
       AUTOFD response per MDPPFS.C SendByte sequence. Caller
       holds state_mutex_. */
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
