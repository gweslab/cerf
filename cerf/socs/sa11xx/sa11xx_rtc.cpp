#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "sa11xx_intc.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

namespace {

/* SA-1110 Dev Man §9.3.5 "Trim Procedure": RTTR (+0x08) corrects
   physical-crystal error only, so it never scales the emulated rate. */

constexpr uint32_t kRtsrAl  = 0x1u;   /* bit 0: alarm detected (W1C)       */
constexpr uint32_t kRtsrHz  = 0x2u;   /* bit 1: 1-Hz rising edge (W1C)     */
constexpr uint32_t kRtsrAle = 0x4u;   /* bit 2: alarm interrupt enable     */
constexpr uint32_t kRtsrHze = 0x8u;   /* bit 3: 1-Hz interrupt enable      */

/* §9.2.1.1 Table 9-1 ICPR source bits. */
constexpr uint32_t kIntcAlarmBit = 1u << 31;  /* IP31: RTC equals alarm    */
constexpr uint32_t kIntcHzBit    = 1u << 30;  /* IP30: one-Hz clock TIC     */

class Sa11xxRtc : public Peripheral {
public:
    using Peripheral::Peripheral;

    ~Sa11xxRtc() override { StopTickThread(); }

    /* Stop the tick thread before any peer is destroyed: it drives an
       interrupt level into the SoC INTC, so it must not outlive it. */
    void OnShutdown() override { StopTickThread(); }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        next_tick_   = Clock::now() + std::chrono::seconds(1);
        tick_thread_ = std::thread(&Sa11xxRtc::TickLoop, this);
    }

    uint32_t MmioBase() const override { return 0x90010000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    using Clock = std::chrono::steady_clock;

    /* §9.3 reset states: RCNR / RTAR / RTTR are uninitialized after
       hardware reset ("undefined after nRESET"); RTSR HZE/ALE = 0,
       HZ/AL = unknown. CERF picks 0 for the unknown bits - guest
       code clears the W1C bits before relying on them. */
    mutable std::mutex state_mtx_;
    uint32_t rtar_ = 0;
    uint32_t rcnr_ = 0;
    uint32_t rttr_ = 0;
    uint32_t rtsr_ = 0;
    Clock::time_point next_tick_ = {};

    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             tick_thread_;
    std::atomic<bool>       stop_{false};

    static constexpr uint32_t kRttrMask = 0x03FFFFFFu;  /* bits 25:0 */
    static constexpr uint32_t kRtsrMask = 0x0000000Fu;  /* bits  3:0 */

    uint32_t ReadRegLocked(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);

    /* §9.2.1.1: drive the RTC interrupt LEVELS into the INTC - alarm
       line = AL & ALE, HZ line = HZ & HZE. Caller holds state_mtx_. */
    void PushLevelLocked() const {
        uint32_t level = 0;
        if ((rtsr_ & kRtsrAl) && (rtsr_ & kRtsrAle)) level |= kIntcAlarmBit;
        if ((rtsr_ & kRtsrHz) && (rtsr_ & kRtsrHze)) level |= kIntcHzBit;
        emu_.Get<Sa11xxIntc>().SetSourceLevel(kIntcAlarmBit | kIntcHzBit, level);
    }

    void NotifyTickThread() {
        std::lock_guard<std::mutex> g(cv_mtx_);
        cv_.notify_all();
    }

    void StopTickThread() {
        stop_.store(true, std::memory_order_release);
        NotifyTickThread();
        if (tick_thread_.joinable()) tick_thread_.join();
    }

    void TickLoop();
};

uint32_t Sa11xxRtc::ReadRegLocked(uint32_t off) const {
    switch (off) {
        case 0x00: return rtar_;
        case 0x04: return rcnr_;
        case 0x08: return rttr_ & kRttrMask;
        case 0x10: return rtsr_ & kRtsrMask;
        default:   return 0;  /* handled by caller via halt. */
    }
}

void Sa11xxRtc::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x00:
            rtar_ = value;
            break;
        case 0x04:
            /* OEMSetRealTime writes RCNR; re-anchor the tick phase so the
               next 1-Hz edge is a full second after the new value. */
            rcnr_ = value;
            next_tick_ = Clock::now() + std::chrono::seconds(1);
            NotifyTickThread();
            break;
        case 0x08:
            rttr_ = value & kRttrMask;
            break;
        case 0x10:
            /* RTSR §9.3.3: HZE/ALE (bits 3,2) are plain R/W; HZ/AL
               (bits 1,0) are W1C. Reserved 31:4 ignored on write. */
            rtsr_ = (rtsr_ & ~(value & 0x3u) & 0x3u)  /* W1C-cleared status */
                  | (value & 0xCu);                   /* R/W enables        */
            rtsr_ &= kRtsrMask;
            PushLevelLocked();
            break;
        default:
            break;
    }
}

void Sa11xxRtc::TickLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    while (!stop_.load(std::memory_order_acquire)) {
        Clock::time_point deadline;
        { std::lock_guard<std::mutex> sg(state_mtx_); deadline = next_tick_; }

        {
            std::unique_lock<std::mutex> lk(cv_mtx_);
            cv_.wait_until(lk, deadline,
                           [&] { return stop_.load(std::memory_order_acquire); });
        }
        if (stop_.load(std::memory_order_acquire)) break;
        if (Clock::now() < deadline) continue;  /* a write re-anchored next_tick_ */

        auto frozen = freeze.WorkerSection();
        std::lock_guard<std::mutex> sg(state_mtx_);
        if (Clock::now() < next_tick_) continue;  /* re-anchored under the lock */

        /* §9.3: increment on the 1-Hz rising edge, then set HZ and compare
           against RTAR for the alarm. */
        rcnr_ += 1u;
        next_tick_ += std::chrono::seconds(1);
        if (next_tick_ < Clock::now()) next_tick_ = Clock::now() + std::chrono::seconds(1);
        rtsr_ |= kRtsrHz;
        if (rcnr_ == rtar_) rtsr_ |= kRtsrAl;
        PushLevelLocked();
    }
}

uint8_t Sa11xxRtc::ReadByte(uint32_t addr) {
    const uint32_t off  = addr - MmioBase();
    const uint32_t base = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base == 0x00 || base == 0x04 || base == 0x08 || base == 0x10) {
        std::lock_guard<std::mutex> sg(state_mtx_);
        return static_cast<uint8_t>((ReadRegLocked(base) >> shift) & 0xFFu);
    }
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

uint32_t Sa11xxRtc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x00 || off == 0x04 || off == 0x08 || off == 0x10) {
        std::lock_guard<std::mutex> sg(state_mtx_);
        return ReadRegLocked(off);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa11xxRtc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base != 0x00 && base != 0x04 && base != 0x08 && base != 0x10) {
        HaltUnsupportedAccess("WriteByte", addr, value);
    }
    std::lock_guard<std::mutex> sg(state_mtx_);
    const uint32_t cur     = ReadRegLocked(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    const uint32_t merged  = cleared | (static_cast<uint32_t>(value) << shift);
    WriteReg(base, merged);
}

void Sa11xxRtc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x00 || off == 0x04 || off == 0x08 || off == 0x10) {
        std::lock_guard<std::mutex> sg(state_mtx_);
        WriteReg(off, value);
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Sa11xxRtc::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> sg(state_mtx_);
    w.Write("rtar", rtar_);  w.Write("rcnr", rcnr_);  w.Write("rttr", rttr_);  w.Write("rtsr", rtsr_);
}

void Sa11xxRtc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> sg(state_mtx_);
    r.Read("rtar", rtar_);  r.Read("rcnr", rcnr_);  r.Read("rttr", rttr_);  r.Read("rtsr", rtsr_);
    /* Wall-clock counter: anchor the next 1-Hz edge one second after the
       restore so RCNR resumes ticking from its restored value. */
    next_tick_ = Clock::now() + std::chrono::seconds(1);
}

void Sa11xxRtc::PostRestore() {
    /* Re-drive the RTC interrupt level after every peripheral (incl. the
       INTC) has been restored - a level-driving source must re-assert its
       line in PostRestore (see agent_docs/hibernation.md). */
    std::lock_guard<std::mutex> sg(state_mtx_);
    PushLevelLocked();
}

}  /* namespace */

REGISTER_SERVICE(Sa11xxRtc);
