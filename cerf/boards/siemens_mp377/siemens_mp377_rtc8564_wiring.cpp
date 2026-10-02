#include "../../peripherals/rtc8564/rtc8564_wiring.h"

#include "../board_context.h"
#include "siemens_mp377_id.h"
#include "../../core/cerf_emulator.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/irq_controller.h"

namespace {

class SiemensMp377Rtc8564Wiring final : public Rtc8564Wiring {
public:
    using Rtc8564Wiring::Rtc8564Wiring;

    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetBoardId() == BoardId::SiemensMp377;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] { Drive(); });
    }

    void SetInterrupt(bool active) override {
        level_ = active;
        Drive();
    }

    int CalendarYearBase() const override { return 1980; }

    /* siemens_mp377 NK.bin RTC8564.dll sub_2B31150: the driver's init writes
       Control2 0x11, alarms 00, CLKOUT 00, timer control 0x82 and timer 01. */
    Retained RetainedRegisters() const override {
        Retained r;
        r.control2      = 0x11u;
        r.timer_control = 0x82u;
        r.timer         = 0x01u;
        return r;
    }

private:
    /* Intel 81341/81342 section 11.4.1 (printed p. 744): XINT[15:8]# are
       level-detect inputs; Table 468 (printed p. 771): INTCTL1 bit 2 is XINT10#.
       Epson RTC-8564 JE/NB datasheet (p. 1): no reset input, /INT open drain. */
    void Drive() {
        if (level_)
            emu_.Get<IrqController>().AssertIrq(0x22);
        else
            emu_.Get<IrqController>().DeAssertIrq(0x22);
    }

    bool level_ = false;
};

REGISTER_SERVICE_AS(SiemensMp377Rtc8564Wiring, Rtc8564Wiring);

} // namespace
