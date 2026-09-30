#include "sa11xx_gpio.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "../../host/guest_deep_sleep.h"
#include "../guest_cpu_reset.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "sa11xx_intc.h"

bool Sa11xxGpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxGpio::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    /* SA-1110 Dev Man §9.5.3, second step of sleep shutdown: "All potential
       wake-up sources are cleared. This involves clearing all the GPIO edge
       detect status bits". SA-1100 TRM §9.5.3 carries the same step. */
    emu_.Get<GuestDeepSleep>().RegisterSleepEntryListener([this] {
        std::unique_lock<std::mutex> lk(mtx_);
        gedr_ = 0;
        PublishEdgeSourcesLocked();
    });
    /* SA-1110 Dev Man §9.1.1.2 GPDR, §9.1.1.4 GRER / GFER reset rows, §9.1.1.6 GAFR "all
       reset conditions"; §9.6: "Sleep reset does not affect the power manager, RTC, or GPIO
       wake-up register". */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
        std::unique_lock<std::mutex> lk(mtx_);
        const uint32_t mask_before = OutputMaskLocked();
        gafr_ = 0;
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
            grer_ |= 0x3u;
            gfer_ |= 0x3u;
            if (kind == ResetLineKind::Rtc) gpdr_ = 0;
        }
        const uint32_t mask = OutputMaskLocked();
        if (mask == mask_before) return;
        const uint32_t levels = output_state_ & mask;
        lk.unlock();
        NotifyOutputs(levels, mask, false);
    });
}

/* SA-1110 Dev Man §9.5.7.7 PGSR: "all 28 bits of the output register are
   loaded". */
void Sa11xxGpio::LoadSleepOutputs(uint32_t pgsr) {
    std::unique_lock<std::mutex> lk(mtx_);
    const uint32_t mask   = OutputMaskLocked();
    const uint32_t before = output_state_ & mask;
    output_state_ = pgsr & kPinMask;
    const uint32_t levels = output_state_ & mask;
    if (levels == before) return;
    lk.unlock();
    NotifyOutputs(levels, mask, false);
}

void Sa11xxGpio::RegisterOutputObserver(OutputObserver fn) {
    uint32_t levels = 0, mask = 0;
    {
        std::unique_lock<std::mutex> lk(mtx_);
        mask   = OutputMaskLocked();
        levels = output_state_ & mask;
    }
    fn(levels, mask, true);
    output_observers_.push_back(std::move(fn));
}

void Sa11xxGpio::NotifyOutputs(uint32_t levels, uint32_t out_mask, bool resync) {
    for (auto& fn : output_observers_) fn(levels, out_mask, resync);
}

Sa11xxGpio::PinConfig Sa11xxGpio::Pin(uint32_t pin) const {
    const uint32_t bit = 1u << pin;
    std::unique_lock<std::mutex> lk(mtx_);
    return {(gpdr_ & bit) != 0u, (gafr_ & bit) != 0u, (output_state_ & bit) != 0u};
}

void Sa11xxGpio::RegisterPinConfigListener(std::function<void()> fn) {
    pin_config_listeners_.push_back(std::move(fn));
}

uint32_t Sa11xxGpio::InputEdges() const {
    std::unique_lock<std::mutex> lk(mtx_);
    return gedr_ & ~gpdr_ & kPinMask;
}

void Sa11xxGpio::DriveInputPin(uint32_t pin, bool level) {
    const uint32_t bit = 1u << pin;
    std::unique_lock<std::mutex> lk(mtx_);
    const uint32_t old = input_state_;
    input_state_ = level ? (input_state_ | bit) : (input_state_ & ~bit);
    if (old == input_state_) return;

    /* §9.1.1.5: an edge matching GRER/GFER latches the GEDR bit. Edge
       detect applies to the pin state regardless of direction; CERF only
       drives input pins here. */
    const bool rising = level;
    const bool latched =
        (rising && (grer_ & bit)) || (!rising && (gfer_ & bit));
    if (latched) {
        gedr_ |= bit;
        PublishEdgeSourcesLocked();
    }
}

/* ICPR sources 0..10 follow GEDR bits 0..10; source 11 is the OR of GEDR
   27..11 (§9.2.1.1). GEDR is the latch, so the ICPR view is a level. */
void Sa11xxGpio::PublishEdgeSourcesLocked() {
    const uint32_t gedr = gedr_;
    auto& intc = emu_.Get<Sa11xxIntc>();
    intc.SetSourceLevel(0x7FFu, gedr & 0x7FFu);
    intc.SetSourceLevel(1u << 11,
                        (gedr & 0x0FFFF800u) ? (1u << 11) : 0u);
}

uint32_t Sa11xxGpio::ReadReg(uint32_t off) {
    std::unique_lock<std::mutex> lk(mtx_);
    switch (off) {
        case 0x00: return ReadGplrLocked();                    /* GPLR R-O */
        case 0x04: return gpdr_ & kPinMask;                    /* GPDR R/W */
        case 0x08: return 0;                                   /* GPSR W-O, read unpredictable */
        case 0x0C: return 0;                                   /* GPCR W-O, read unpredictable */
        case 0x10: return grer_ & kPinMask;                    /* GRER R/W */
        case 0x14: return gfer_ & kPinMask;                    /* GFER R/W */
        case 0x18: return gedr_ & kPinMask;                    /* GEDR R/W (W1C) */
        case 0x1C: return gafr_ & kPinMask;                    /* GAFR R/W */
        default:
            emu_.Get<Fatal>().Die("Sa11xxGpio: read of unmapped offset +0x%02X", off);
    }
}

void Sa11xxGpio::WriteReg(uint32_t off, uint32_t value) {
    const uint32_t v = value & kPinMask;
    std::unique_lock<std::mutex> lk(mtx_);
    const uint32_t mask_before   = OutputMaskLocked();
    const uint32_t levels_before = output_state_ & mask_before;
    const uint32_t gpdr_before   = gpdr_;
    const uint32_t gafr_before   = gafr_;
    const uint32_t latch_before  = output_state_;
    switch (off) {
        case 0x00: break;                                      /* GPLR R-O, writes ignored */
        case 0x04: gpdr_ = v; break;
        case 0x08: output_state_ = (output_state_ | (v & gpdr_)) & kPinMask; break;
        case 0x0C: output_state_ &= ~(v & gpdr_); break;
        case 0x10: grer_ = v; break;
        case 0x14: gfer_ = v; break;
        case 0x18: gedr_ &= ~v; PublishEdgeSourcesLocked(); break;  /* W1C */
        case 0x1C: gafr_ = v; break;
        default:
            emu_.Get<Fatal>().Die("Sa11xxGpio: write of unmapped offset +0x%02X", off);
    }
    const uint32_t mask   = OutputMaskLocked();
    const uint32_t levels = output_state_ & mask;
    const bool pins_changed = gpdr_ != gpdr_before || gafr_ != gafr_before ||
                              output_state_ != latch_before;
    lk.unlock();
    if (mask != mask_before || levels != levels_before) NotifyOutputs(levels, mask, false);
    if (!pins_changed) return;
    for (auto& fn : pin_config_listeners_) fn();
}

uint32_t Sa11xxGpio::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off > 0x1C || (off & 0x3u) != 0) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxGpio::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off > 0x1C || (off & 0x3u) != 0) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

void Sa11xxGpio::SaveState(StateWriter& w) {
    std::unique_lock<std::mutex> lk(mtx_);
    w.Write("output_state", output_state_);
    w.Write("input_state", input_state_);
    w.Write("gpdr", gpdr_);
    w.Write("grer", grer_);
    w.Write("gfer", gfer_);
    w.Write("gedr", gedr_);
    w.Write("gafr", gafr_);
}

void Sa11xxGpio::RestoreState(StateReader& r) {
    std::unique_lock<std::mutex> lk(mtx_);
    r.Read("output_state", output_state_);
    r.Read("input_state", input_state_);
    r.Read("gpdr", gpdr_);
    r.Read("grer", grer_);
    r.Read("gfer", gfer_);
    r.Read("gedr", gedr_);
    r.Read("gafr", gafr_);
}

void Sa11xxGpio::PostRestore() {
    /* Re-establish the GEDR->ICPR source levels into the INTC, which the
       INTC's own RestoreState can't know about. */
    std::unique_lock<std::mutex> lk(mtx_);
    PublishEdgeSourcesLocked();
    const uint32_t mask   = OutputMaskLocked();
    const uint32_t levels = output_state_ & mask;
    lk.unlock();
    NotifyOutputs(levels, mask, true);
}

REGISTER_SERVICE(Sa11xxGpio);
