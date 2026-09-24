#include "p2_fpga_serial.h"

#include "../../state/state_stream.h"

uint16_t P2FpgaSerial::Read(uint32_t slot_off) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (slot_off == kSlotCsrA) return csr_a_;
    return csr_b_;
}

bool P2FpgaSerial::Write(uint32_t slot_off, uint16_t value) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (slot_off == kSlotCsrA) {
        /* W1C: clear bits where (value & kCsrAW1cMask) is 1. */
        csr_a_ &= static_cast<uint16_t>(~(value & kCsrAW1cMask));
        /* R/W bits: copy from write value. The W1C and R/W
           masks are disjoint (0xF618 & 0x0901 = 0); R/O bits
           ignored. */
        csr_a_ = static_cast<uint16_t>((csr_a_ & ~kCsrARwMask)
                                     | (value & kCsrARwMask));
        return false;
    }
    /* CSR B all R/W. Detect SERB_TX_EN 0→1 transition. */
    const uint16_t old_csr_b = csr_b_;
    csr_b_ = value;
    return !(old_csr_b & kSerbTxEn) && (value & kSerbTxEn);
}

void P2FpgaSerial::SetCsrABits(uint16_t bits) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    csr_a_ |= bits;
}

void P2FpgaSerial::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    w.Write("csr_a", csr_a_);
    w.Write("csr_b", csr_b_);
}

void P2FpgaSerial::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    r.Read("csr_a", csr_a_);
    r.Read("csr_b", csr_b_);
}
