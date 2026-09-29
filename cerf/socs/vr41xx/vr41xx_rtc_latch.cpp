#include "vr41xx_rtc_latch.h"

#include "../../state/state_stream.h"

bool Vr41xxRtcLatch::Write(uint32_t half, uint16_t value) {
    const uint32_t shift = half * 16u;
    value_    = ((value_ & ~(0xFFFFull << shift)) | (uint64_t{value} << shift)) & mask_;
    written_ |= static_cast<uint8_t>(1u << half);
    if (written_ != (1u << halves_) - 1u) return false;
    written_ = 0u;
    return true;
}

void Vr41xxRtcLatch::Clear() {
    value_   = 0u;
    written_ = 0u;
}

void Vr41xxRtcLatch::Save(StateWriter& w, const char* value_name, const char* written_name) const {
    w.Write(value_name, value_);
    w.Write(written_name, written_);
}

void Vr41xxRtcLatch::Restore(StateReader& r, const char* value_name, const char* written_name) {
    r.Read(value_name, value_);
    r.Read(written_name, written_);
}
