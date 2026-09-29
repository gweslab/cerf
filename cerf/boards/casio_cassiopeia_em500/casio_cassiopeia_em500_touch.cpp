#include "casio_cassiopeia_em500_touch.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"

#include <algorithm>

namespace {

constexpr uint32_t kOffCtrl300  = 0x0300u;
constexpr uint32_t kOffParam308 = 0x0308u;
constexpr uint32_t kOffParam30C = 0x030Cu;
constexpr uint32_t kOffParam310 = 0x0310u;
constexpr uint32_t kOffParam318 = 0x0318u;
constexpr uint32_t kOffCfg3C8   = 0x03C8u;
constexpr uint32_t kOffAdc0 = 0x0320u;
constexpr uint32_t kOffAdc1 = 0x0350u;

/* touch.dll sub_F91DDC @0xF91E16 (bit0) / loc_F91B62 @0xF91B70 (bit2) go strobes. */
constexpr uint32_t kCtrlGoBits = 0x5u;
/* touch.dll loc_F91958 @0xF919C0/@0xF919CA: 0x300 & 0x1C00 == 0x1400/0x1800
   reloads the settle counter (loc_F91A24, dword_F9411C=5) = pen actively down;
   any other value decrements it @0xF919D0 = pen lifting. */
constexpr uint32_t kPenStateMask   = 0x1C00u;
constexpr uint32_t kPenStateActive = 0x1400u;

constexpr uint32_t kOffIntCause0304 = 0x0304u;
constexpr uint32_t kIntEnableMask   = 0xFF00u;
/* casio_cassiopeia_em500_ppc2000 touch.dll @0xF91A40-@0xF91A44 (|= 1), @0xF91B48 (|= 0x18);
   casio_cassiopeia_em500_ppc2000 nk_main_kernel.exe @0x9F036754-@0x9F036770 (stores 0). */
constexpr uint32_t kIntStatusMask   = 0x00FFu;
constexpr uint32_t kStatusPenEvent  = 0x01u;
constexpr uint32_t kStatusSample    = 0x18u;

/* touch.dll loc_F91D40 @0xF91D54 (& 0xFFF, 12-bit A/D). */
constexpr uint16_t kAdcMax = 0x0FFFu;

uint16_t ToAdc(int surface_coord) {
    /* touch.dll TouchPanelCalibrateAPoint @0xF92344: uncalibrated (dword_F94144==0)
       passes the raw sample through unchanged, so gwes consumes it as the guest
       pixel coordinate. */
    int v = surface_coord;
    if (v < 0) v = 0;
    if (v > static_cast<int>(kAdcMax)) v = static_cast<int>(kAdcMax);
    return static_cast<uint16_t>(v);
}

}

void CasioCassiopeiaEm500Touch::Init(CerfEmulator& emu, std::function<void()> on_status_change) {
    emu_              = &emu;
    on_status_change_ = std::move(on_status_change);
    clock_        = &emu.Get<GuestCycleClock>();
    sample_event_ = clock_->Add([this] { OnSampleEvent(); });
    clock_->RegisterRateListener([this] { OnRateChange(); });
    host_requests_ = &emu.Get<HostRequestChannel>();
    host_requests_->RegisterListener([this] { OnHostRequest(); });
}

bool CasioCassiopeiaEm500Touch::TryReadWord(uint32_t off, uint32_t& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (off >= kOffAdc0 && off < kOffAdc0 + 16u && (off & 3u) == 0u) {
        out = adc0_[(off - kOffAdc0) / 4u]; return true;
    }
    if (off >= kOffAdc1 && off < kOffAdc1 + 16u && (off & 3u) == 0u) {
        out = adc1_[(off - kOffAdc1) / 4u]; return true;
    }
    switch (off) {
        case kOffCtrl300: out = ctrl_300_ & ~kCtrlGoBits; return true;
        case kOffCfg3C8:  out = cfg_3C8_; return true;
        case kOffIntCause0304: out = int_enable_.load(std::memory_order_acquire) | Status(); return true;
        default: return false;
    }
}

bool CasioCassiopeiaEm500Touch::TryWriteWord(uint32_t off, uint32_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (off >= kOffAdc0 && off < kOffAdc0 + 16u && (off & 3u) == 0u) {
        adc0_[(off - kOffAdc0) / 4u] = static_cast<uint16_t>(value & kAdcMax); return true;
    }
    if (off >= kOffAdc1 && off < kOffAdc1 + 16u && (off & 3u) == 0u) {
        adc1_[(off - kOffAdc1) / 4u] = static_cast<uint16_t>(value & kAdcMax); return true;
    }
    switch (off) {
        case kOffCtrl300:  ctrl_300_ = value; return true;
        case kOffParam308:
            param_308_ = value;
            if (sampling_) RescaleSamplesLocked();
            else if (param_308_ != 0u && SamplingLocked()) StartSamplingLocked();
            return true;
        case kOffParam30C: param_30C_ = value; return true;
        case kOffParam310: param_310_ = value; return true;
        case kOffParam318: param_318_ = value; return true;
        case kOffCfg3C8:   cfg_3C8_ = value; return true;
        case kOffIntCause0304:
            int_enable_.store(value & kIntEnableMask, std::memory_order_release);
            ClearStatus(value & kIntStatusMask);
            NotifyStatus();
            return true;
        default: return false;
    }
}

uint32_t CasioCassiopeiaEm500Touch::Status() const {
    return (sample_pending_.load(std::memory_order_acquire) ? kStatusSample : 0u) |
           (pen_event_.load(std::memory_order_acquire) ? kStatusPenEvent : 0u);
}

void CasioCassiopeiaEm500Touch::ClearStatus(uint32_t bits) {
    if (bits & kStatusSample)   sample_pending_.store(false, std::memory_order_release);
    if (bits & kStatusPenEvent) pen_event_.store(false, std::memory_order_release);
}

bool CasioCassiopeiaEm500Touch::IrqPending() const {
    return (Status() & (int_enable_.load(std::memory_order_acquire) >> 8) & kIntStatusMask) != 0u;
}

void CasioCassiopeiaEm500Touch::NotifyStatus() {
    on_status_change_();
}

bool CasioCassiopeiaEm500Touch::TryReadByte(uint32_t, uint8_t&)   { return false; }
bool CasioCassiopeiaEm500Touch::TryWriteByte(uint32_t, uint8_t)   { return false; }
bool CasioCassiopeiaEm500Touch::TryReadHalf(uint32_t, uint16_t&)  { return false; }
bool CasioCassiopeiaEm500Touch::TryWriteHalf(uint32_t, uint16_t)  { return false; }

void CasioCassiopeiaEm500Touch::SetPen(bool down, int surface_x, int surface_y) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        host_pen_.push_back(HostPen{down, surface_x, surface_y});
        host_x_ = surface_x;
        host_y_ = surface_y;
    }
    host_requests_->Request();
}

void CasioCassiopeiaEm500Touch::OnCaptureLost() {
    int x, y;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        x = host_x_;
        y = host_y_;
    }
    SetPen(false, x, y);
}

void CasioCassiopeiaEm500Touch::PresentDownLocked() {
    const uint16_t xp = raw_x_;
    const uint16_t xm = static_cast<uint16_t>(kAdcMax - raw_x_);
    const uint16_t yp = raw_y_;
    const uint16_t ym = static_cast<uint16_t>(kAdcMax - raw_y_);
    adc0_[0] = adc1_[0] = xp;
    adc0_[1] = adc1_[1] = xm;
    adc0_[2] = adc1_[2] = yp;
    adc0_[3] = adc1_[3] = ym;
    ctrl_300_ = (ctrl_300_ & ~kPenStateMask) | kPenStateActive;
    sample_pending_.store(true, std::memory_order_release);
    NotifyStatus();
}

void CasioCassiopeiaEm500Touch::PresentLiftLocked() {
    ctrl_300_ &= ~kPenStateMask;
    sample_pending_.store(false, std::memory_order_release);
    NotifyStatus();
}

void CasioCassiopeiaEm500Touch::OnHostRequest() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (host_pen_.empty()) return;
    std::vector<HostPen> pens;
    pens.swap(host_pen_);
    for (const HostPen& p : pens) ApplyPenLocked(p.down, p.x, p.y);
}

void CasioCassiopeiaEm500Touch::ApplyPenLocked(bool down, int surface_x, int surface_y) {
    raw_x_ = ToAdc(surface_x);
    raw_y_ = ToAdc(surface_y);
    /* casio_cassiopeia_em500_ppc2000 touch.dll loc_F91958 @0xF91A46-@0xF91A5E: 0x304 bit 0 with
       the driver idle (dword_F94118 == 0) starts a stroke and arms its gate via sub_F916D4. */
    if (down && !pen_down_) pen_event_.store(true, std::memory_order_release);
    pen_down_ = down;
    if (down) PresentDownLocked();
    else      PresentLiftLocked();
    if (!sampling_ && pen_down_ && param_308_ != 0u) StartSamplingLocked();
}

/* casio_cassiopeia_em500_ppc2000 touch.dll: sub_F917F0 (TouchPanelSetMode) and sub_F91DDC store
   +0x308 = 1500; sub_F91C44 reports one point per 3 samples; sub_F91798 index 0 = {375, 500}. */
uint64_t CasioCassiopeiaEm500Touch::SampleHzLocked() const {
    if (param_308_ == 0u) {
        emu_->Get<Fatal>().Die("Em500Touch: companion +0x308 set to 0 while the pen is sampled");
    }
    return param_308_;
}

void CasioCassiopeiaEm500Touch::StartSamplingLocked() {
    const GuestCycleClock::Rate rate = clock_->ClockRate();
    const uint64_t hz = SampleHzLocked();
    if (rate.den > UINT64_MAX / hz || !samples_.SetRatio(rate.num, rate.den * hz)) {
        emu_->Get<Fatal>().Die("Em500Touch: %llu samples/s against the %llu/%llu Hz core does "
                               "not fit", static_cast<unsigned long long>(hz),
                               static_cast<unsigned long long>(rate.num),
                               static_cast<unsigned long long>(rate.den));
    }
    samples_.Anchor(clock_->Cycles(), 0u);
    next_sample_ = 1u;
    sampling_    = true;
    ArmSampleLocked();
}

void CasioCassiopeiaEm500Touch::ArmSampleLocked() {
    clock_->Arm(sample_event_, samples_.NextMatchCycle(next_sample_, clock_->Cycles()));
}

void CasioCassiopeiaEm500Touch::OnSampleEvent() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!sampling_) return;
    SampleLocked();
    if (!SamplingLocked()) {
        sampling_ = false;
        return;
    }
    next_sample_ = samples_.CountAt(clock_->Cycles()) + 1u;
    ArmSampleLocked();
}

void CasioCassiopeiaEm500Touch::SampleLocked() {
    if (pen_down_) PresentDownLocked();
}

void CasioCassiopeiaEm500Touch::OnRateChange() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (sampling_) RescaleSamplesLocked();
}

void CasioCassiopeiaEm500Touch::RescaleSamplesLocked() {
    const GuestCycleClock::Rate rate = clock_->ClockRate();
    const uint64_t hz = SampleHzLocked();
    if (rate.den > UINT64_MAX / hz || !samples_.Rescale(clock_->Cycles(), rate.num, rate.den * hz)) {
        emu_->Get<Fatal>().Die("Em500Touch: %llu samples/s against the %llu/%llu Hz core does "
                               "not fit", static_cast<unsigned long long>(hz),
                               static_cast<unsigned long long>(rate.num),
                               static_cast<unsigned long long>(rate.den));
    }
    ArmSampleLocked();
}

void CasioCassiopeiaEm500Touch::SaveState(StateWriter& w) const {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("ctrl_300", ctrl_300_);
    w.Write("param_308", param_308_); w.Write("param_30C", param_30C_); w.Write("param_310", param_310_); w.Write("param_318", param_318_);
    w.Write("cfg_3C8", cfg_3C8_);
    for (uint16_t v : adc0_) w.Write("adc0", v);
    for (uint16_t v : adc1_) w.Write("adc1", v);
    w.Write("int_enable_0304", int_enable_.load(std::memory_order_acquire));
}

void CasioCassiopeiaEm500Touch::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("ctrl_300", ctrl_300_);
    r.Read("param_308", param_308_); r.Read("param_30C", param_30C_); r.Read("param_310", param_310_); r.Read("param_318", param_318_);
    r.Read("cfg_3C8", cfg_3C8_);
    for (uint16_t& v : adc0_) r.Read("adc0", v);
    for (uint16_t& v : adc1_) r.Read("adc1", v);
    uint32_t int_enable = 0;
    r.Read("int_enable_0304", int_enable);
    int_enable_.store(int_enable, std::memory_order_release);
    pen_down_ = false;
    sampling_ = false;
    host_pen_.clear();
    clock_->Disarm(sample_event_);
    sample_pending_.store(false, std::memory_order_release);
    pen_event_.store(false, std::memory_order_release);
}

void CasioCassiopeiaEm500Touch::PostRestore() {}
