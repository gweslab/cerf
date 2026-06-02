#include "twl4030.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"

namespace {
constexpr uint8_t kTwlAddr_USB         = 0x48;
constexpr uint8_t kTwlAddr_AUDIO_INTBR = 0x49;
constexpr uint8_t kTwlAddr_BCI_MADC    = 0x4A;
constexpr uint8_t kTwlAddr_PWR_RTC     = 0x4B;
}  /* namespace */

bool Twl4030::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::OMAP3530;
}

bool Twl4030::MatchesAddress(uint8_t slave_addr) const {
    return slave_addr == kTwlAddr_USB         ||
           slave_addr == kTwlAddr_AUDIO_INTBR ||
           slave_addr == kTwlAddr_BCI_MADC    ||
           slave_addr == kTwlAddr_PWR_RTC;
}

void Twl4030::TxnStart(uint8_t slave_addr) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const int idx = AddrIndex(slave_addr);
    sub_addr_pending_[idx] = true;
}

void Twl4030::TxnWriteByte(uint8_t slave_addr, uint8_t byte) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const int idx = AddrIndex(slave_addr);
    if (sub_addr_pending_[idx]) {
        sub_addr_[idx] = byte;
        sub_addr_pending_[idx] = false;
        return;
    }
    regs_[idx][sub_addr_[idx]] = byte;
    sub_addr_[idx] = (sub_addr_[idx] + 1u) & 0xFFu;
}

uint8_t Twl4030::TxnReadByte(uint8_t slave_addr) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const int idx = AddrIndex(slave_addr);
    const uint8_t v = regs_[idx][sub_addr_[idx]];
    sub_addr_[idx] = (sub_addr_[idx] + 1u) & 0xFFu;
    return v;
}

int Twl4030::AddrIndex(uint8_t slave_addr) {
    switch (slave_addr) {
    case kTwlAddr_USB:         return 0;
    case kTwlAddr_AUDIO_INTBR: return 1;
    case kTwlAddr_BCI_MADC:    return 2;
    case kTwlAddr_PWR_RTC:     return 3;
    }
    LOG(Caution, "Twl4030: AddrIndex called with unknown slave_addr "
            "0x%02X — bus dispatch should have rejected this\n",
            slave_addr);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

REGISTER_SERVICE(Twl4030);
