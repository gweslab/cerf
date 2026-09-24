#include "vrc5477_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/rate_probe.h"
#include "../../boards/board_context.h"
#include "../../cpu/vr5500/vr5500_id.h"
#include "../../jit/mips/mips_jit.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {
enum : uint32_t {
    kINTCTRL0 = 0x00, kINTCTRL1 = 0x04, kINTCTRL2 = 0x08, kINTCTRL3 = 0x0C,
    kINT0STAT = 0x20, kINT1STAT = 0x28, kINT2STAT = 0x30, kINT3STAT = 0x38,
    kINT4STAT = 0x40, kNMISTAT  = 0x50, kINTCLR32 = 0x68,
    kINTPPES0 = 0x70, kINTPPES1 = 0x78, kCPUSTAT  = 0x80, kBUSCTRL  = 0x88,
};

constexpr uint32_t kIpForOutput0 = 1u << 10;
}  /* namespace */

REGISTER_SERVICE(Vrc5477Intc);

bool Vrc5477Intc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Vr5500;
}

uint32_t Vrc5477Intc::StatusForLineLocked(uint32_t n) const {
    uint32_t s = 0;
    for (uint32_t irq = 0; irq < 32; ++irq) {
        const uint32_t nib = (intctrl_[irq >> 3] >> ((irq & 7u) * 4u)) & 0xFu;
        if ((nib & 0x8u) && (nib & 0x7u) == n && (pending_ & (1u << irq))) {
            s |= (1u << irq);
        }
    }
    return s;
}

void Vrc5477Intc::NotifyLocked() {
    uint32_t ip = 0;
    for (uint32_t n = 0; n < 4; ++n) {
        if (StatusForLineLocked(n) != 0) ip |= kIpForOutput0 << n;
    }
    emu_.Get<MipsJit>().SetExternalInterruptLevel(ip);
}

void Vrc5477Intc::AssertSource(uint32_t irq) {
    if (irq >= 32) return;
    std::lock_guard<std::mutex> lk(state_mtx_);
    const uint32_t mask = 1u << irq;
    line_level_ |= mask;
    if ((pending_ & mask) == 0) {
        pending_ |= mask;
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::IntcAsserts);
        NotifyLocked();
    }
}

void Vrc5477Intc::DeassertSource(uint32_t irq) {
    if (irq >= 32) return;
    std::lock_guard<std::mutex> lk(state_mtx_);
    const uint32_t mask = 1u << irq;
    line_level_ &= ~mask;
    if ((pending_ & mask) != 0) {
        pending_ &= ~mask;
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::IntcDeasserts);
        NotifyLocked();
    }
}

uint32_t Vrc5477Intc::ReadReg(uint32_t off) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    switch (off) {
        case kINTCTRL0: return intctrl_[0];
        case kINTCTRL1: return intctrl_[1];
        case kINTCTRL2: return intctrl_[2];
        case kINTCTRL3: return intctrl_[3];
        case kINT0STAT: return StatusForLineLocked(0);
        case kINT1STAT: return StatusForLineLocked(1);
        case kINT2STAT: return StatusForLineLocked(2);
        case kINT3STAT: return StatusForLineLocked(3);
        case kINT4STAT: return StatusForLineLocked(4);
        case kNMISTAT:  return nmistat_;
        case kINTCLR32: return pending_;
        case kINTPPES0: return intppes0_;
        case kINTPPES1: return intppes1_;
        case kCPUSTAT:  return cpustat_;
        case kBUSCTRL:  return busctrl_;
        default:        return 0;
    }
}

void Vrc5477Intc::WriteReg(uint32_t off, uint32_t value) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    switch (off) {
        case kINTCTRL0: intctrl_[0] = value; NotifyLocked(); break;
        case kINTCTRL1: intctrl_[1] = value; NotifyLocked(); break;
        case kINTCTRL2: intctrl_[2] = value; NotifyLocked(); break;
        case kINTCTRL3: intctrl_[3] = value; NotifyLocked(); break;
        case kINTCLR32:
            pending_ = (pending_ & ~value) | line_level_;  /* W1C clears edge latches; level sources follow their still-driven line */
            NotifyLocked(); break;
        case kINTPPES0: intppes0_ = value; break;
        case kINTPPES1: intppes1_ = value; break;
        case kCPUSTAT:  cpustat_  = value; break;
        case kBUSCTRL:  busctrl_  = value; break;
        default:        break;                        /* INTnSTAT/NMISTAT read-only */
    }
}

void Vrc5477Intc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    for (uint32_t v : intctrl_) w.Write("intctrl", v);
    w.Write("intppes0", intppes0_); w.Write("intppes1", intppes1_);
    w.Write("cpustat", cpustat_);  w.Write("busctrl", busctrl_); w.Write("nmistat", nmistat_); w.Write("pending", pending_);
    w.Write("line_level", line_level_);
}

void Vrc5477Intc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    for (uint32_t& v : intctrl_) r.Read("intctrl", v);
    r.Read("intppes0", intppes0_); r.Read("intppes1", intppes1_);
    r.Read("cpustat", cpustat_);  r.Read("busctrl", busctrl_); r.Read("nmistat", nmistat_); r.Read("pending", pending_);
    r.Read("line_level", line_level_);
}

void Vrc5477Intc::Renotify() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    NotifyLocked();
}
