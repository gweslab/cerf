#include "mc13783.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/arm_processor_config.h"
#include "../../jit/arm_jit.h"
#include "../../jit/cpu_state.h"

#include <chrono>

REGISTER_SERVICE(Mc13783);

namespace {

constexpr uint32_t kRegRtcTime    = 20;
constexpr uint32_t kRegRtcDay     = 22;
constexpr uint32_t kSecondsPerDay = 86400u;

constexpr auto kRebaseInterval = std::chrono::seconds(1);

}  /* namespace */

Mc13783::~Mc13783() {
    stop_.store(true, std::memory_order_release);
    cv_.notify_all();
    if (rebase_thread_.joinable()) rebase_thread_.join();
}

bool Mc13783::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetBoard() == Board::ZuneKeel;
}

void Mc13783::OnReady() {
    arm_clk_hz_ = emu_.Get<ArmProcessorConfig>().CpuClockHz();
    baseline_packed_.store(PackBaseline(0u, GuestCycles()),
                           std::memory_order_release);
    rebase_thread_ = std::thread([this] { RebaseLoop(); });
}

uint32_t Mc13783::GuestCycles() const {
    return emu_.Get<ArmJit>().CpuState()->guest_cycle_counter;
}

uint32_t Mc13783::RtcTotalSecs() const {
    const uint64_t packed = baseline_packed_.load(std::memory_order_acquire);
    const uint32_t delta  = GuestCycles() - UnpackCycles(packed);
    return UnpackSecs(packed) + (delta / arm_clk_hz_);
}

void Mc13783::RebaseToCurrent() {
    const uint64_t old_packed = baseline_packed_.load(std::memory_order_acquire);
    const uint32_t cycles_now = GuestCycles();
    const uint32_t delta      = cycles_now - UnpackCycles(old_packed);
    const uint32_t advance    = delta / arm_clk_hz_;
    const uint32_t new_secs   = UnpackSecs(old_packed) + advance;
    const uint32_t new_cycles = UnpackCycles(old_packed) + advance * arm_clk_hz_;
    baseline_packed_.store(PackBaseline(new_secs, new_cycles),
                           std::memory_order_release);
}

void Mc13783::RebaseLoop() {
    std::unique_lock<std::mutex> lk(cv_mtx_);
    while (!stop_.load(std::memory_order_acquire)) {
        lk.unlock();
        RebaseToCurrent();
        lk.lock();
        if (stop_.load(std::memory_order_acquire)) break;
        cv_.wait_for(lk, kRebaseInterval);
    }
}

uint32_t Mc13783::SpiExchange(uint32_t cmd) {
    const bool     write = ((cmd >> 31) & 1u) != 0;
    const uint32_t addr  = (cmd >> 25) & 0x3Fu;
    const uint32_t data  = cmd & 0x00FFFFFFu;

    if (write) {
        const uint32_t prev = regs_[addr];
        regs_[addr] = data;
        LOG(Periph, "[MC13783] WRITE reg=%u (0x%02X) data=0x%06X\n",
            addr, addr, data);
        return prev;
    }

    uint32_t value;
    if      (addr == kRegRtcTime) value = RtcTotalSecs() % kSecondsPerDay;
    else if (addr == kRegRtcDay)  value = (RtcTotalSecs() / kSecondsPerDay) & kRtcDayMask;
    else                          value = regs_[addr] & 0x00FFFFFFu;

    LOG(Periph, "[MC13783] READ  reg=%u (0x%02X) value=0x%06X\n",
        addr, addr, value);
    return value;
}
