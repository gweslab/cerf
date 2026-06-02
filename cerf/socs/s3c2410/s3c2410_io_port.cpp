#include "s3c2410_io_port.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"

namespace {

/* S3C2410 chip-ID per user manual section 9.6 (GSTATUS1). The
   DeviceEmulator BSP and other S3C2410-targeting OALs probe this
   register to confirm chip family before writing GPIO config. */
constexpr uint32_t kRegOffsetGstatus1   = 0xB0u;
constexpr uint32_t kGstatus1ChipIdValue = 0x32410000u;

/* EINT4..7 share SRCPND bit 4, EINT8..23 share bit 5 (silicon
   rollup); OAL demuxes via EINTPEND. */
int MainSourceBitForEint(int n) {
    if (n <= 3) return n;
    if (n <= 7) return 4;
    return 5;
}

}  /* namespace */

bool S3C2410IoPort::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::S3C2410;
}

void S3C2410IoPort::OnReady() {
    storage_[kRegOffsetGstatus1 / 4u] = kGstatus1ChipIdValue;
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t S3C2410IoPort::ReadWord(uint32_t addr) {
    const uint32_t slot = (addr - MmioBase()) / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    uint32_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        value = storage_[slot];
    }
    return value;
}

void S3C2410IoPort::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t slot = (addr - MmioBase()) / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (slot) {
        case kSlotEintPend:
            /* W1C — write 1 to clear the corresponding latched edge.
               The kernel ISR drops the pend bit before returning. */
            storage_[slot] &= ~value;
            break;
        default:
            storage_[slot] = value;
            break;
    }
}

void S3C2410IoPort::AssertEint(int n) {
    if (n < 0 || n >= 24) {
        LOG(Caution, "S3C2410IoPort::AssertEint: n=%d out of range "
                "(EINT0..23)\n", n);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    bool     unmasked = false;
    uint32_t pend_after;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t bit = 1u << n;
        storage_[kSlotEintPend] |= bit;
        pend_after = storage_[kSlotEintPend];
        unmasked   = (storage_[kSlotEintMask] & bit) == 0;
    }
    LOG(SocIoport, "AssertEint(%d): EINTPEND=0x%08X unmasked=%d\n",
        n, pend_after, (int)unmasked);
    if (unmasked) {
        emu_.Get<IrqController>().AssertIrq(MainSourceBitForEint(n));
    }
}

void S3C2410IoPort::ClearEint(int n) {
    if (n < 0 || n >= 24) {
        LOG(Caution, "S3C2410IoPort::ClearEint: n=%d out of range "
                "(EINT0..23)\n", n);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        storage_[kSlotEintPend] &= ~(1u << n);
    }
    LOG(SocIoport, "ClearEint(%d)\n", n);
}

REGISTER_SERVICE(S3C2410IoPort);
