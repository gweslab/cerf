#include "mediaq_ge.h"

#include "../../core/log.h"
#include "../../state/state_stream.h"

#include <cstring>

void MediaQGe::WriteReg(uint32_t g, uint32_t value) {
    if (g >= kNumRegs) return;
    reg_[g] = value;
    if (g == kGe00Command) Execute();
}

uint32_t MediaQGe::BytesPerPixel() const {
    /* GE0AR[31:30] colour depth (MQ-200 Data Book Table 5-73): 00=8, 01=16,
       11=32 bpp; 10 reserved. */
    switch ((reg_[kGe0ADstStride] >> 30) & 3u) {
        case 0:  return 1u;
        case 1:  return 2u;
        case 3:  return 4u;
        default: return 0u;
    }
}

uint32_t MediaQGe::Rop3(uint8_t rop, uint32_t p, uint32_t s, uint32_t d) {
    uint32_t r = 0u;
    if (rop & 0x01u) r |= ~p & ~s & ~d;
    if (rop & 0x02u) r |= ~p & ~s &  d;
    if (rop & 0x04u) r |= ~p &  s & ~d;
    if (rop & 0x08u) r |= ~p &  s &  d;
    if (rop & 0x10u) r |=  p & ~s & ~d;
    if (rop & 0x20u) r |=  p & ~s &  d;
    if (rop & 0x40u) r |=  p &  s & ~d;
    if (rop & 0x80u) r |=  p &  s &  d;
    return r;
}

void MediaQGe::Execute() {
    /* A new command means the prior system-source command's stream has ended;
       draw it from its snapshot before the live registers change. */
    if (pending_active_) ExecutePending();

    const uint32_t cmd  = reg_[kGe00Command];
    const uint32_t type = (cmd >> kCmdTypeShift) & kCmdTypeMask;
    const uint8_t  rop  = static_cast<uint8_t>(cmd & kCmdRopMask);

    if (type == kTypeNop) return;
    if (type == kTypeLine) { DrawLine(cmd); return; }

    if (type == kTypeBitBlt) {
        if (cmd & kCmdSrcSystem) {
            std::memcpy(pending_reg_, reg_, sizeof(reg_));
            src_fifo_.clear();
            expected_dwords_ = ExpectedSourceDwords();
            pending_active_  = true;
            if (expected_dwords_ == 0u) ExecutePending();   /* empty blit. */
            return;
        }
        if (IsSolidFill(cmd)) { FillSolid(rop, SolidFillColor(), cmd); return; }
        if (cmd & kCmdMonoSrc) BlitMonoFromDisplay(cmd);
        else                   BlitColorFromDisplay(cmd);
        return;
    }

    LOG(Caution, "MediaQ GE: unimplemented command 0x%08X (type=%u rop=0x%02X)\n",
        cmd, type, rop);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void MediaQGe::PushSourceFifo(uint32_t value) {
    src_fifo_.push_back(value);
    if (pending_active_ && src_fifo_.size() >= expected_dwords_) ExecutePending();
}

void MediaQGe::FlushPending() {
    if (pending_active_ && src_fifo_.size() >= expected_dwords_) ExecutePending();
}

void MediaQGe::ExecutePending() {
    pending_active_ = false;
    if (pending_reg_[kGe00Command] & kCmdMonoSrc) BlitMonoSource(pending_reg_);
    else                                          BlitColorSource(pending_reg_);
    src_fifo_.clear();
}

void MediaQGe::SaveState(StateWriter& w) const {
    w.WriteBytes("reg", reg_, sizeof(reg_));
    w.Write<uint64_t>("src_fifo_count", src_fifo_.size());
    if (!src_fifo_.empty())
        w.WriteBytes("src_fifo", src_fifo_.data(), src_fifo_.size() * sizeof(uint32_t));
    w.WriteBytes("pending_reg", pending_reg_, sizeof(pending_reg_));
    w.Write<uint8_t>("pending_active", pending_active_ ? 1u : 0u);
    w.Write("expected_dwords", expected_dwords_);
}

void MediaQGe::RestoreState(StateReader& r) {
    r.ReadBytes("reg", reg_, sizeof(reg_));
    uint64_t n = 0; r.Read("src_fifo_count", n);
    src_fifo_.assign(static_cast<size_t>(n), 0u);
    if (n) r.ReadBytes("src_fifo", src_fifo_.data(), static_cast<size_t>(n) * sizeof(uint32_t));
    r.ReadBytes("pending_reg", pending_reg_, sizeof(pending_reg_));
    uint8_t a = 0; r.Read("pending_active", a); pending_active_ = (a != 0);
    r.Read("expected_dwords", expected_dwords_);
}
