#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <mutex>

namespace {

/* Kernel reads via BOTH 16-bit REG (CFWP2.C:266-270) AND 32-bit
   struct (ARMINT.C:66) — must share storage with 32-bit
   zero-extending the high half. */

constexpr uint32_t kPcmciaPaBase   = 0x10000410u;
constexpr uint32_t kPcmciaSize     = 0x10u;

constexpr uint32_t kSlotPcmciaReg0     = 0x00u;  /* PA +0x10 from CPU_BASE */
constexpr uint32_t kSlotPcmciaIntrReg0 = 0x04u;  /* PA +0x14 */
constexpr uint32_t kSlotPcmciaReg1     = 0x08u;  /* PA +0x18 */
constexpr uint32_t kSlotPcmciaIntrReg1 = 0x0Cu;  /* PA +0x1C */

constexpr uint16_t kPcmciaStateIntr = 0x0001u;   /* P2.H line 455 */

class OdoArm720Pcmcia : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kPcmciaPaBase; }
    uint32_t MmioSize() const override { return kPcmciaSize; }

    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static bool IsControlSlot(uint32_t off) {
        return off == kSlotPcmciaReg0 || off == kSlotPcmciaReg1;
    }
    static bool IsIntrSlot(uint32_t off) {
        return off == kSlotPcmciaIntrReg0 || off == kSlotPcmciaIntrReg1;
    }
    static char SlotIndex(uint32_t off) {
        return (off == kSlotPcmciaReg0 || off == kSlotPcmciaIntrReg0)
                   ? '0' : '1';
    }

    mutable std::mutex state_mutex_;
    uint16_t           pcmcia_reg0_      = 0;
    uint16_t           pcmcia_intr_reg0_ = 0;
    uint16_t           pcmcia_reg1_      = 0;
    uint16_t           pcmcia_intr_reg1_ = 0;
};

uint16_t OdoArm720Pcmcia::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint16_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if      (off == kSlotPcmciaReg0)     value = pcmcia_reg0_;
        else if (off == kSlotPcmciaIntrReg0) value = pcmcia_intr_reg0_;
        else if (off == kSlotPcmciaReg1)     value = pcmcia_reg1_;
        else if (off == kSlotPcmciaIntrReg1) value = pcmcia_intr_reg1_;
        else HaltUnsupportedAccess("ReadHalf", addr, 0);
    }
#if CERF_DEV_MODE
    LOG(Pcmcia, "Odo PCMCIA read16 +0x%02X -> 0x%04X\n", off, value);
#endif
    return value;
}

void OdoArm720Pcmcia::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
#if CERF_DEV_MODE
    LOG(Pcmcia, "Odo PCMCIA write16 +0x%02X = 0x%04X\n", off, value);
#endif
    if (IsControlSlot(off)) {
        if (value != 0) {
            LOG(Caution, "Odo PCMCIA: activation write to "
                    "PCMCIA_REG%c = 0x%04X — non-zero control "
                    "bits set, no host PCMCIA model behind this "
                    "peripheral.\n", SlotIndex(off), value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (off == kSlotPcmciaReg0) pcmcia_reg0_ = value;
        else                        pcmcia_reg1_ = value;
        return;
    }
    if (IsIntrSlot(off)) {
        if ((value & ~kPcmciaStateIntr) != 0) {
            /* P2.H:455 — bits 1-4 are R/O line states (PCMCIA_INTR
               / CD1/CD2/WP). Allowing W1C on them clears bits the
               hardware drives, falsifying card-detect state. */
            LOG(Caution, "Odo PCMCIA: write to PCMCIA_INTR_REG%c = "
                    "0x%04X — bits other than PCMCIA_STATE_INTR "
                    "(0x0001) set; only bit 0 is documented W1C.\n",
                    SlotIndex(off), value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (off == kSlotPcmciaIntrReg0) {
            pcmcia_intr_reg0_ &= static_cast<uint16_t>(
                                    ~(value & kPcmciaStateIntr));
        } else {
            pcmcia_intr_reg1_ &= static_cast<uint16_t>(
                                    ~(value & kPcmciaStateIntr));
        }
        return;
    }
    HaltUnsupportedAccess("WriteHalf", addr, value);
}

uint32_t OdoArm720Pcmcia::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint16_t value16;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if      (off == kSlotPcmciaReg0)     value16 = pcmcia_reg0_;
        else if (off == kSlotPcmciaIntrReg0) value16 = pcmcia_intr_reg0_;
        else if (off == kSlotPcmciaReg1)     value16 = pcmcia_reg1_;
        else if (off == kSlotPcmciaIntrReg1) value16 = pcmcia_intr_reg1_;
        else HaltUnsupportedAccess("ReadWord", addr, 0);
    }
#if CERF_DEV_MODE
    LOG(Pcmcia, "Odo PCMCIA read32 +0x%02X -> 0x%08X\n",
        off, static_cast<uint32_t>(value16));
#endif
    return static_cast<uint32_t>(value16);
}

void OdoArm720Pcmcia::WriteWord(uint32_t addr, uint32_t value) {
    if ((value & 0xFFFF0000u) != 0) {
        /* P2.H lines 442-455 define only bits 0-7 of each PCMCIA
           register; bits 16-31 are undocumented. A 32-bit write
           with non-zero high 16 bits is an unverified bit
           pattern — halt rather than truncate silently. */
        LOG(Caution, "Odo PCMCIA: WriteWord at 0x%08X = 0x%08X has "
                "non-zero high 16 bits; only bits 0-7 are defined "
                "per P2.H lines 442-455.\n", addr, value);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    WriteHalf(addr, static_cast<uint16_t>(value & 0xFFFFu));
}

}  /* namespace */

REGISTER_SERVICE(OdoArm720Pcmcia);
