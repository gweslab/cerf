#include "devemu_keyboard_controller.h"

#include "../../boards/board_context.h"
#include "devemu_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/cpu_state.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/s3c2410/s3c2410_eint_source.h"
#include "../../socs/s3c2410/s3c2410_spi.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <chrono>
#include <iterator>

namespace {

constexpr int kSpiChannel = 1;

constexpr int  kEintNumber   = 1;
constexpr bool kPinIdle      = true;
constexpr bool kPinDataReady = false;

/* S3C2410A UM p. 22-7, SPCONn TAGD note: "In normal mode, if you only want to
   receive data, you should transmit dummy 0xFF data."; p. 22-5 "Receiving
   Procedure by DMA" step 6: "Write data 0xFF automatically to SPTDATn." */
constexpr uint8_t kHostDummy = 0xFFu;

constexpr uint8_t kCommandPrefix = 0x1Bu;

constexpr uint8_t kCommands[][3] = {
    { 0x1Bu, 0xA0u, 0x7Bu },
    { 0x1Bu, 0xA1u, 0x7Au },
};

constexpr uint8_t kNoScancodeResponse = 0xFFu;

constexpr uint32_t kAckWindowCyclesObserved = 8538u;
constexpr uint32_t kReassertDelayCycles     = 4u * kAckWindowCyclesObserved;

constexpr auto kDeadlinePollInterval = std::chrono::microseconds(50);

}

bool DevEmuKeyboardController::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Devemu;
}

void DevEmuKeyboardController::OnReady() {
    emu_.Get<S3C2410Spi>().SetSlave(kSpiChannel, this);
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { ResetDevice(); });
    worker_ = std::thread([this] { DeadlineLoop(); });
}

void DevEmuKeyboardController::OnShutdown() {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) { worker_.join(); }
}

void DevEmuKeyboardController::QueueScancode(uint8_t scancode) {
    {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        std::lock_guard<std::mutex> lk(mutex_);
        queue_.push_back(scancode);
        ArmPresentationLocked();
    }
    cv_.notify_all();
}

uint8_t DevEmuKeyboardController::Exchange(uint8_t mosi) {
    uint8_t scancode = 0;
    bool    had_byte = false;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        AcceptHostByteLocked(mosi);
        if (!queue_.empty()) {
            scancode = queue_.front();
            queue_.pop_front();
            had_byte = true;
        }
        DriveLineLocked(kPinIdle);
        line_active_ = false;
        armed_       = false;
        ArmPresentationLocked();
    }
    cv_.notify_all();
    return had_byte ? scancode : kNoScancodeResponse;
}

void DevEmuKeyboardController::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mutex_);
    w.Write<uint32_t>("queue_count", static_cast<uint32_t>(queue_.size()));
    for (uint8_t b : queue_) { w.Write<uint8_t>("queue", b); }
    w.Write<uint32_t>("deadline", deadline_);
    w.Write<uint32_t>("cmd_index", cmd_index_);
    w.Write<uint32_t>("cmd_pos", cmd_pos_);
    w.Write<uint8_t>("armed", static_cast<uint8_t>(armed_));
    w.Write<uint8_t>("line_active", static_cast<uint8_t>(line_active_));
    w.Write<uint8_t>("line_seeded", static_cast<uint8_t>(line_seeded_));
}

void DevEmuKeyboardController::RestoreState(StateReader& r) {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        queue_.clear();
        uint32_t count = 0;
        r.Read("queue_count", count);
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t b = 0;
            r.Read("queue", b);
            queue_.push_back(b);
        }
        r.Read("deadline", deadline_);
        r.Read("cmd_index", cmd_index_);
        r.Read("cmd_pos", cmd_pos_);
        uint8_t armed = 0, active = 0, seeded = 0;
        r.Read("armed", armed);
        r.Read("line_active", active);
        r.Read("line_seeded", seeded);
        armed_       = armed  != 0;
        line_active_ = active != 0;
        line_seeded_ = seeded != 0;
    }
    cv_.notify_all();
}

void DevEmuKeyboardController::ResetDevice() {
    std::lock_guard<std::mutex> lk(mutex_);
    queue_.clear();
    cmd_pos_   = 0;
    cmd_index_ = 0;
    armed_     = false;
    DriveLineLocked(kPinIdle);
    line_active_ = false;
    line_seeded_ = true;
}

void DevEmuKeyboardController::DriveLineLocked(bool level) {
    emu_.Get<S3C2410EintSource>().DriveEintPin(kEintNumber, level);
}

void DevEmuKeyboardController::ArmPresentationLocked() {
    if (queue_.empty() || line_active_ || armed_) { return; }
    if (!line_seeded_) {
        DriveLineLocked(kPinIdle);
        line_seeded_ = true;
    }
    deadline_ = GuestCycles() + kReassertDelayCycles;
    armed_    = true;
}

void DevEmuKeyboardController::AcceptHostByteLocked(uint8_t mosi) {
    switch (cmd_pos_) {
        case 0:
            if (mosi == kHostDummy) { return; }
            if (mosi == kCommandPrefix) { cmd_pos_ = 1; return; }
            break;
        case 1:
            for (uint32_t i = 0; i < std::size(kCommands); ++i) {
                if (mosi == kCommands[i][1]) {
                    cmd_index_ = i;
                    cmd_pos_   = 2;
                    return;
                }
            }
            break;
        default:
            if (cmd_index_ < std::size(kCommands) &&
                mosi == kCommands[cmd_index_][2]) {
                cmd_pos_ = 0;
                return;
            }
            break;
    }
    emu_.Get<Fatal>().Die(
        "DevEmuKeyboardController: host shifted 0x%02X at command byte %u, "
        "which no known command sequence carries there", mosi, cmd_pos_);
}

uint32_t DevEmuKeyboardController::GuestCycles() const {
    return emu_.Get<ArmJit>().CpuState()->guest_cycle_counter;
}

void DevEmuKeyboardController::DeadlineLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    for (;;) {
        {
            std::unique_lock<std::mutex> lk(mutex_);
            cv_.wait(lk, [this] { return stop_ || armed_; });
            if (stop_) { return; }
        }

        for (;;) {
            {
                auto frozen = freeze.WorkerSection();
                std::lock_guard<std::mutex> lk(mutex_);
                if (stop_)   { return; }
                if (!armed_) { break; }
                if (static_cast<int32_t>(GuestCycles() - deadline_) >= 0) {
                    armed_ = false;
                    if (!queue_.empty() && !line_active_) {
                        DriveLineLocked(kPinDataReady);
                        line_active_ = true;
                    }
                    break;
                }
            }
            std::this_thread::sleep_for(kDeadlinePollInterval);
        }
    }
}

REGISTER_SERVICE(DevEmuKeyboardController);
