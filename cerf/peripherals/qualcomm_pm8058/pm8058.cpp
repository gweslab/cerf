#include "../ssbi_slave.h"

#include "pm8058_gpio.h"
#include "pm8058_irq.h"
#include "pm8058_keypad.h"
#include "pm8058_rtc.h"

#include "../../boards/board_context.h"
#include "../../boards/nokia_lumia_800/nokia_lumia_800_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Linux drivers/mfd/pm8058-core.c: REG_HWREV 0x0002, REG_IRQ_ROOT 0x01bb,
   REG_IRQ_M_STATUS1..4 0x01bc..0x01bf, REG_IRQ_BLK_SEL 0x01c0,
   REG_IRQ_IT_STATUS 0x01c1, REG_IRQ_CONFIG 0x01c2, REG_IRQ_RT_STATUS 0x01c3. */
constexpr uint16_t kRegHwrev     = 0x0002u;
constexpr uint16_t kRegIrqRoot   = 0x01BBu;
constexpr uint16_t kRegIrqMaster = 0x01BCu;
constexpr uint16_t kRegIrqBlkSel = 0x01C0u;
constexpr uint16_t kRegIrqStatus = 0x01C1u;
constexpr uint16_t kRegIrqConfig = 0x01C2u;
constexpr uint16_t kRegIrqRtStat = 0x01C3u;

constexpr uint16_t kRegCount = 0x0400u;

constexpr uint8_t kHwrevModelNibble    = 0xEu;
constexpr uint8_t kHwrevRevisionNibble = 0x0u;
constexpr uint8_t kHwrev =
    (uint8_t)((kHwrevModelNibble << 4) | kHwrevRevisionNibble);

class Pm8058 : public SsbiSlave {
public:
    using SsbiSlave::SsbiSlave;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetListener(
            [this](ResetLineKind) { probe_next_ = 1u; });
    }

    uint8_t ReadReg(uint16_t reg) override {
        if (reg >= kRegCount) {
            emu_.Get<Fatal>().Die(
                "pm8058: read of register 0x%03X is outside the %u the part "
                "addresses", reg, kRegCount);
        }

        const bool probe = reg == probe_next_;
        if (probe && ++probe_next_ >= kRegCount) probe_next_ = kRegCount;

        if (reg == kRegHwrev) return kHwrev;

        if (Pm8058Keypad::Owns(reg)) {
            return emu_.Get<Pm8058Keypad>().ReadReg(reg);
        }
        if (Pm8058Gpio::Owns(reg)) {
            return emu_.Get<Pm8058Gpio>().ReadReg(reg);
        }
        if (Pm8058Rtc::Owns(reg)) {
            return emu_.Get<Pm8058Rtc>().ReadReg(reg);
        }

        auto& irq = emu_.Get<Pm8058Irq>();
        switch (reg) {
        case kRegIrqRoot:   return irq.ReadRoot();
        case kRegIrqBlkSel: return irq.ReadBlockSelect();
        case kRegIrqStatus: return irq.ReadItStatus();
        case kRegIrqConfig: return irq.ReadConfig();
        case kRegIrqRtStat: return irq.ReadRtStatus();
        default: break;
        }
        if (reg >= kRegIrqMaster && reg < kRegIrqMaster + Pm8058Irq::kMasters) {
            return irq.ReadMaster((uint32_t)(reg - kRegIrqMaster));
        }

        if (!probe) {
            emu_.Get<Fatal>().Die(
                "pm8058: register 0x%03X is read outside the ascending boot "
                "walk of the whole register file, and nothing models what it "
                "holds", reg);
        }
        return 0u;
    }

    void WriteReg(uint16_t reg, uint8_t value) override {
        if (reg >= kRegCount) {
            emu_.Get<Fatal>().Die(
                "pm8058: write of 0x%02X to register 0x%03X is outside the %u "
                "the part addresses", value, reg, kRegCount);
        }

        if (Pm8058Keypad::Owns(reg)) {
            emu_.Get<Pm8058Keypad>().WriteReg(reg, value);
            return;
        }
        if (Pm8058Gpio::Owns(reg)) {
            emu_.Get<Pm8058Gpio>().WriteReg(reg, value);
            return;
        }
        if (Pm8058Rtc::Owns(reg)) {
            emu_.Get<Pm8058Rtc>().WriteReg(reg, value);
            return;
        }

        auto& irq = emu_.Get<Pm8058Irq>();
        switch (reg) {
        case kRegIrqBlkSel:
            irq.WriteBlockSelect(value);
            return;
        case kRegIrqConfig:
            irq.WriteConfig(value);
            return;
        default:
            break;
        }

        emu_.Get<Fatal>().Die(
            "pm8058: nothing models a write of 0x%02X to register 0x%03X",
            value, reg);
    }

    void SaveState(StateWriter& w) override {
        emu_.Get<Pm8058Irq>().SaveState(w);
        emu_.Get<Pm8058Keypad>().SaveState(w);
        emu_.Get<Pm8058Gpio>().SaveState(w);
        emu_.Get<Pm8058Rtc>().SaveState(w);
        w.Write<uint16_t>("probe_next", probe_next_);
    }

    void RestoreState(StateReader& r) override {
        emu_.Get<Pm8058Irq>().RestoreState(r);
        emu_.Get<Pm8058Keypad>().RestoreState(r);
        emu_.Get<Pm8058Gpio>().RestoreState(r);
        emu_.Get<Pm8058Rtc>().RestoreState(r);
        r.Read("probe_next", probe_next_);
        if (probe_next_ > kRegCount) {
            r.Reject(
                "pm8058: restored boot-walk position 0x%03X is past the %u "
                "registers the part addresses", probe_next_, kRegCount);
        }
    }

    void PostRestore() override { emu_.Get<Pm8058Irq>().RepublishOutput(); }

private:
    uint16_t probe_next_ = 1u;
};

}  // namespace

REGISTER_SERVICE_AS(Pm8058, SsbiSlave);
