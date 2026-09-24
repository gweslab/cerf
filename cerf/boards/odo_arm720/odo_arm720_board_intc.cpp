#include "odo_arm720_board_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/cpu_state.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../state/state_stream.h"

#include <mutex>

namespace {

constexpr uint32_t kBoardIntcPaBase   = 0x10000800u;
constexpr uint32_t kBoardIntcSize     = 0x08u;        /* cpuIsr + cpuMr */

constexpr uint32_t kSlotCpuIsr        = 0x00u;
constexpr uint32_t kSlotCpuMr         = 0x04u;

}  /* namespace */

bool OdoArm720BoardIntc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Odo;
}

bool OdoArm720BoardIntc::HasPendingUnmaskedLocked() const {
    return timer_irq_level_ || (cpu_isr_ & cpu_mr_) != 0;
}

void OdoArm720BoardIntc::PublishIrqLineLocked() {
    auto& jit = emu_.Get<ArmJit>();
    if (HasPendingUnmaskedLocked()) jit.SetInterruptPending();
    else                            jit.ClearInterruptPending();
}

void OdoArm720BoardIntc::NotifyJitInterruptState() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    PublishIrqLineLocked();
}

void OdoArm720BoardIntc::SetTimerIrqLevel(bool level) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    timer_irq_level_ = level;
    PublishIrqLineLocked();
}

void OdoArm720BoardIntc::AssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= 32) {
        LOG(Caution, "OdoArm720BoardIntc::AssertIrq: source_bit %d "
                "out of range - cpuIsr/cpuMr are 32-bit registers\n",
                source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        cpu_isr_ |= (1u << source_bit);
    }
    NotifyJitInterruptState();
}

void OdoArm720BoardIntc::DeAssertIrq(int source_bit) {
    if (source_bit < 0 || source_bit >= 32) {
        LOG(Caution, "OdoArm720BoardIntc::DeAssertIrq: source_bit "
                "%d out of range\n", source_bit);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        cpu_isr_ &= ~(1u << source_bit);
    }
    NotifyJitInterruptState();
}

void OdoArm720BoardIntc::AssertSubIrq(int main_source_bit, int sub_source_bit) {
    LOG(Caution, "OdoArm720BoardIntc::AssertSubIrq: Odo board "
            "INTC has no sub-interrupt register (main=%d, sub=%d) "
            "- caller is targeting the wrong SoC\n",
            main_source_bit, sub_source_bit);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

uint32_t OdoArm720BoardIntc::ReadReg32(uint32_t offset) {
    if (offset != kSlotCpuIsr && offset != kSlotCpuMr) {
        LOG(Caution, "OdoArm720BoardIntc::ReadReg32: offset 0x%X "
                "out of range - only 0x00 (cpuIsr) and 0x04 (cpuMr) "
                "are modeled\n", offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint32_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        value = (offset == kSlotCpuIsr) ? cpu_isr_ : cpu_mr_;
    }
#if CERF_DEV_MODE
    LOG(SocIntc, "Odo BoardIntc read32  +0x%02X -> 0x%08X\n",
        offset, value);
#endif
    return value;
}

uint16_t OdoArm720BoardIntc::ReadReg16(uint32_t offset) {
    const uint32_t slot_offset = offset & ~0x2u;     /* round down to 4-byte slot */
    if (slot_offset != kSlotCpuIsr && slot_offset != kSlotCpuMr) {
        LOG(Caution, "OdoArm720BoardIntc::ReadReg16: offset 0x%X "
                "out of range\n", offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    uint32_t slot_value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        slot_value = (slot_offset == kSlotCpuIsr) ? cpu_isr_ : cpu_mr_;
    }
    const uint16_t value =
        (offset & 0x2u) ? static_cast<uint16_t>(slot_value >> 16)
                        : static_cast<uint16_t>(slot_value & 0xFFFFu);
#if CERF_DEV_MODE
    LOG(SocIntc, "Odo BoardIntc read16  +0x%02X -> 0x%04X\n",
        offset, value);
#endif
    return value;
}

void OdoArm720BoardIntc::WriteReg32(uint32_t offset, uint32_t value) {
    if (offset != kSlotCpuIsr && offset != kSlotCpuMr) {
        LOG(Caution, "OdoArm720BoardIntc::WriteReg32: offset 0x%X "
                "out of range\n", offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
#if CERF_DEV_MODE
    LOG(SocIntc, "Odo BoardIntc write32 +0x%02X = 0x%08X\n",
        offset, value);
#endif
    if (offset == kSlotCpuIsr) {
        LOG(Caution, "OdoArm720BoardIntc::WriteReg32 cpuIsr=0x%08X "
                "- no modeled write semantic for cpuIsr; scope must be "
                "extended with the right semantic before continuing\n",
                value);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        cpu_mr_ = value;
    }
    NotifyJitInterruptState();
}

void OdoArm720BoardIntc::WriteReg16(uint32_t offset, uint16_t value) {
    const uint32_t slot_offset = offset & ~0x2u;
    if (slot_offset != kSlotCpuIsr && slot_offset != kSlotCpuMr) {
        LOG(Caution, "OdoArm720BoardIntc::WriteReg16: offset 0x%X "
                "out of range\n", offset);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
#if CERF_DEV_MODE
    LOG(SocIntc, "Odo BoardIntc write16 +0x%02X = 0x%04X\n",
        offset, value);
#endif
    if (slot_offset == kSlotCpuIsr) {
        LOG(Caution, "OdoArm720BoardIntc::WriteReg16 cpuIsr offset=0x%X "
                "value=0x%04X - no modeled write semantic for cpuIsr; "
                "scope must be extended with the right semantic before "
                "continuing\n",
                offset, value);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        /* Halfword write to cpuMr preserves the other half. */
        const uint32_t mask = (offset & 0x2u) ? 0x0000FFFFu : 0xFFFF0000u;
        const uint32_t shifted = (offset & 0x2u)
                                   ? (static_cast<uint32_t>(value) << 16)
                                   : static_cast<uint32_t>(value);
        cpu_mr_ = (cpu_mr_ & mask) | shifted;
    }
    NotifyJitInterruptState();
}

void OdoArm720BoardIntc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.Write<uint32_t>("cpu_isr", cpu_isr_);
    w.Write<uint32_t>("cpu_mr", cpu_mr_);
}

void OdoArm720BoardIntc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    r.Read("cpu_isr", cpu_isr_);
    r.Read("cpu_mr", cpu_mr_);
}

void OdoArm720BoardIntc::PostRestore() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    PublishIrqLineLocked();
}

REGISTER_SERVICE_AS(OdoArm720BoardIntc, IrqController);


namespace {

class OdoArm720BoardIntcMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBoardIntcPaBase; }
    uint32_t MmioSize() const override { return kBoardIntcSize; }

    uint32_t ReadWord(uint32_t addr) override {
        auto& intc = static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>());
        return intc.ReadReg32(addr - MmioBase());
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        auto& intc = static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>());
        intc.WriteReg32(addr - MmioBase(), value);
    }
    uint16_t ReadHalf(uint32_t addr) override {
        auto& intc = static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>());
        return intc.ReadReg16(addr - MmioBase());
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        auto& intc = static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>());
        intc.WriteReg16(addr - MmioBase(), value);
    }

    void SaveState(StateWriter& w) override {
        static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>()).SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>()).RestoreState(r);
    }
    void PostRestore() override {
        static_cast<OdoArm720BoardIntc&>(emu_.Get<IrqController>()).PostRestore();
    }
};

}  /* namespace */

REGISTER_SERVICE(OdoArm720BoardIntcMmio);
