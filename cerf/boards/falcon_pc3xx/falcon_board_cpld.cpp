#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../jit/arm_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* Falcon (Askey PC320/PC331) board CPLD at PA 0xA3CC3000 (carved out of DRAM so
   it routes here). nk.exe OEMIoControl 0x101003C (IOCTL_HAL_REBOOT, sub_800F5E20)
   writes 3 to PA 0xA3CC380C (offset 0x80C) to reset the board — trigger the warm
   reset on that write, else the post-reboot OAL spins and WarmCheck never signals. */
class FalconBoardCpld : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::FalconPC3xx;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0xA3CC3000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint8_t  ReadByte (uint32_t addr) override { return regs_[addr - MmioBase()]; }
    uint32_t ReadWord (uint32_t addr) override {
        uint32_t off = addr - MmioBase(), v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(regs_[off + i]) << (8 * i);
        return v;
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = addr - MmioBase();
        regs_[off] = value;
        if (off == kReboot && value == kRebootCmd) TriggerReset();
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        for (int i = 0; i < 4; ++i) regs_[off + i] = static_cast<uint8_t>(value >> (8 * i));
        if (off == kReboot && (value & 0xFFu) == kRebootCmd) TriggerReset();
    }

private:
    static constexpr uint32_t kReboot    = 0x80Cu;  /* PA 0xA3CC380C - base 0xA3CC3000. */
    static constexpr uint32_t kRebootCmd = 3u;

    void TriggerReset() {
        LOG(SocReset, "Falcon CPLD PA 0xA3CC380C=3: board reboot -> SetResetPending\n");
        emu_.Get<ArmJit>().SetResetPending();
    }

    /* +4 tail so a word access at the last in-range offset (0xFFF) cannot
       overrun; the guest only addresses off < 0x1000 (dispatcher contract). */
    uint8_t regs_[0x1000 + 4] = {};
};

}  /* namespace */

REGISTER_SERVICE(FalconBoardCpld);
