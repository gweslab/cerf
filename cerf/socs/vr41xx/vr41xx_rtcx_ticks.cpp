#include "vr41xx_rtcx_ticks.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/mips/mips_interrupt_channel.h"

void Vr41xxRtcxTicks::Bind() {
    channel_ = &emu_.Get<MipsInterruptChannel>();
    OscillatorTicks::Attach(kHz, 1u);
}

void Vr41xxRtcxTicks::Attach() {
    if (domain_ != Vr41xxRtcxDomain::RtcIcuPmu) {
        emu_.Get<Fatal>().Die("Vr41xxRtcxTicks: a peripheral RTCX counter attached with no "
                              "clock-gate callback");
    }
    Bind();
}

void Vr41xxRtcxTicks::Attach(std::function<void()> on_clock_gate) {
    if (domain_ != Vr41xxRtcxDomain::Peripheral || !on_clock_gate) {
        emu_.Get<Fatal>().Die("Vr41xxRtcxTicks: a clock-gate callback on an RTCX counter "
                              "outside the peripheral clock domain");
    }
    Bind();
    channel_->RegisterSuspendListener(std::move(on_clock_gate));
}

uint64_t Vr41xxRtcxTicks::ClockCycles() {
    if (domain_ == Vr41xxRtcxDomain::RtcIcuPmu) return clock_->Cycles();
    return channel_->CyclesOutsideSuspend();
}

bool Vr41xxRtcxTicks::ClockStopped() {
    return domain_ == Vr41xxRtcxDomain::Peripheral && channel_->Suspended();
}
