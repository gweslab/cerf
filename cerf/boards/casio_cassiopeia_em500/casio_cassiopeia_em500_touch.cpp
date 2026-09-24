#include "casio_cassiopeia_em500_touch.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <chrono>

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

/* touch.dll loc_F91D40 @0xF91D54 (& 0xFFF, 12-bit A/D). */
constexpr uint16_t kAdcMax = 0x0FFFu;

/* nk_main_kernel.exe resolver sub_9F0348xx @0x9F0348C4 returns SYSINTR 17 iff
   MEM[0xA0002624] == 0x8001; touch.dll loc_F91958 reads the same word as
   [dword_F94108(0xA0002000)+0x624]. PA 0x2624 runtime-confirmed by the
   em500_wait_probe poke (TryTranslateWrite(0x2624)<-0x8001 delivered SYSINTR 17). */
constexpr uint32_t kGatePa    = 0x00002624u;
constexpr uint32_t kGateArmed = 0x00008001u;

constexpr uint32_t kSampleIntervalMs = 10u;
/* touch.dll loc_F91958: settle counter dword_F9411C init 5 (@0xF91A28), drained
   one per lifting sample (@0xF919D0); the driver emits pen-up (status=1,
   @0xF919E2) when it reaches 0. */
constexpr int kReleaseDrainTicks = 8;

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

CasioCassiopeiaEm500Touch::~CasioCassiopeiaEm500Touch() { StopWorker(); }

void CasioCassiopeiaEm500Touch::Init(CerfEmulator& emu) {
    emu_ = &emu;
    worker_ = std::thread([this] { WorkerLoop(); });
}

void CasioCassiopeiaEm500Touch::OnShutdown() { StopWorker(); }

void CasioCassiopeiaEm500Touch::StopWorker() {
    stop_.store(true, std::memory_order_release);
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
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
        case kOffParam308: param_308_ = value; return true;
        case kOffParam30C: param_30C_ = value; return true;
        case kOffParam310: param_310_ = value; return true;
        case kOffParam318: param_318_ = value; return true;
        case kOffCfg3C8:   cfg_3C8_ = value; return true;
        default: return false;
    }
}

bool CasioCassiopeiaEm500Touch::TryReadByte(uint32_t, uint8_t&)   { return false; }
bool CasioCassiopeiaEm500Touch::TryWriteByte(uint32_t, uint8_t)   { return false; }
bool CasioCassiopeiaEm500Touch::TryReadHalf(uint32_t, uint16_t&)  { return false; }
bool CasioCassiopeiaEm500Touch::TryWriteHalf(uint32_t, uint16_t)  { return false; }

void CasioCassiopeiaEm500Touch::SetPen(bool down, int surface_x, int surface_y) {
    {
        auto frozen = emu_->Get<EmulationFreeze>().WorkerSection();
        std::lock_guard<std::mutex> lk(mtx_);
        /* touch.dll loc_F91958: the release drain must reach the pen-up deliver
           @0xF919E2 (settle drained to 0 @0xF919D0) before a new down. */
        if (down && release_drain_ > 0) {
            pending_down_ = true;
            pending_x_ = ToAdc(surface_x);
            pending_y_ = ToAdc(surface_y);
            return;
        }
        raw_x_ = ToAdc(surface_x);
        raw_y_ = ToAdc(surface_y);
        pen_down_ = down;
        if (down) {
            PresentDownLocked();
        } else {
            release_drain_ = kReleaseDrainTicks;
            pending_down_ = false;
            PresentLiftLocked();
        }
        DepositGate();
    }
    wake_.store(true, std::memory_order_release);
    cv_.notify_all();
}

void CasioCassiopeiaEm500Touch::OnCaptureLost() { SetPen(false, raw_x_, raw_y_); }

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
    release_ack_.store(false, std::memory_order_release);
}

void CasioCassiopeiaEm500Touch::PresentLiftLocked() {
    ctrl_300_ &= ~kPenStateMask;
    sample_pending_.store(false, std::memory_order_release);
    release_ack_.store(true, std::memory_order_release);
}

void CasioCassiopeiaEm500Touch::DepositGate() {
    uint8_t* p = emu_->Get<EmulatedMemory>().TryTranslateWrite(kGatePa);
    if (!p) return;
    cerf::le::Put32(p, kGateArmed);
}

void CasioCassiopeiaEm500Touch::WorkerLoop() {
    auto& freeze = emu_->Get<EmulationFreeze>();
    std::unique_lock<std::mutex> lk(cv_mtx_);
    while (!stop_.load(std::memory_order_acquire)) {
        lk.unlock();
        bool sampling;
        {
            auto frozen = freeze.WorkerSection();
            std::lock_guard<std::mutex> sl(mtx_);
            if (pen_down_) {
                PresentDownLocked();
                DepositGate();
                sampling = true;
            } else if (release_drain_ > 0) {
                PresentLiftLocked();
                DepositGate();
                --release_drain_;
                if (release_drain_ == 0 && pending_down_) {
                    pending_down_ = false;
                    pen_down_ = true;
                    raw_x_ = pending_x_;
                    raw_y_ = pending_y_;
                }
                sampling = true;
            } else {
                sampling = false;
            }
        }
        lk.lock();
        if (stop_.load(std::memory_order_acquire)) break;
        if (sampling) {
            cv_.wait_for(lk, std::chrono::milliseconds(kSampleIntervalMs));
        } else {
            cv_.wait(lk, [this] {
                return stop_.load(std::memory_order_acquire) ||
                       wake_.exchange(false, std::memory_order_acq_rel);
            });
        }
    }
}

void CasioCassiopeiaEm500Touch::SaveState(StateWriter& w) const {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("ctrl_300", ctrl_300_);
    w.Write("param_308", param_308_); w.Write("param_30C", param_30C_); w.Write("param_310", param_310_); w.Write("param_318", param_318_);
    w.Write("cfg_3C8", cfg_3C8_);
    for (uint16_t v : adc0_) w.Write("adc0", v);
    for (uint16_t v : adc1_) w.Write("adc1", v);
}

void CasioCassiopeiaEm500Touch::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("ctrl_300", ctrl_300_);
    r.Read("param_308", param_308_); r.Read("param_30C", param_30C_); r.Read("param_310", param_310_); r.Read("param_318", param_318_);
    r.Read("cfg_3C8", cfg_3C8_);
    for (uint16_t& v : adc0_) r.Read("adc0", v);
    for (uint16_t& v : adc1_) r.Read("adc1", v);
    pen_down_ = false;
    release_drain_ = 0;
    pending_down_ = false;
    sample_pending_.store(false, std::memory_order_release);
    release_ack_.store(false, std::memory_order_release);
}

void CasioCassiopeiaEm500Touch::PostRestore() {}
