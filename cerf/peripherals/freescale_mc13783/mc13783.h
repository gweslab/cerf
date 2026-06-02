#pragma once

#include "../../core/service.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

class Mc13783 : public Service {
public:
    using Service::Service;
    ~Mc13783() override;

    bool ShouldRegister() override;
    void OnReady() override;

    /* MC13783 datasheet §4.1.1.3.1 SPI Transfer Protocol. */
    uint32_t SpiExchange(uint32_t cmd);

private:
    /* MC13783 datasheet Table 5: 64 control fields of 24 bits each. */
    static constexpr uint32_t kRegisterCount = 64;
    uint32_t regs_[kRegisterCount] = {};

    /* §4.1.2.2.1: 17-bit TOD (0..86399), 15-bit DAY (0..32767). */
    static constexpr uint32_t kRtcDayMask = 0x7FFFu;

    /* High 32 = total_secs_so_far, low 32 = guest_cycle_counter
       snapshot. Reading the pair non-atomically races a concurrent
       rebase and produces seconds from one epoch with cycles from
       another, jumping the RTC backwards. */
    std::atomic<uint64_t> baseline_packed_{0};
    uint32_t              arm_clk_hz_{1};

    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             rebase_thread_;
    std::atomic<bool>       stop_{false};

    static uint64_t PackBaseline(uint32_t secs, uint32_t cycles) {
        return (static_cast<uint64_t>(secs) << 32) | cycles;
    }
    static uint32_t UnpackSecs  (uint64_t p) { return static_cast<uint32_t>(p >> 32); }
    static uint32_t UnpackCycles(uint64_t p) { return static_cast<uint32_t>(p); }

    uint32_t GuestCycles() const;
    uint32_t RtcTotalSecs() const;
    void     RebaseToCurrent();
    void     RebaseLoop();
};
