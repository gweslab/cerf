#include "devemu_keyboard_controller.h"

#include "../../boards/board_context.h"
#include "devemu_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/s3c2410/s3c2410_eint_source.h"
#include "../../socs/s3c2410/s3c2410_spi.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <iterator>

namespace {

constexpr int kSpiChannel = 1;

constexpr int  kEintNumber   = 1;
constexpr bool kPinIdle      = true;
constexpr bool kPinDataReady = false;

constexpr uint32_t kEint1IntmskBit = 1u << kEintNumber;

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

}

bool DevEmuKeyboardController::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Devemu;
}

void DevEmuKeyboardController::OnReady() {
    emu_.Get<S3C2410Spi>().SetSlave(kSpiChannel, this);
    emu_.Get<S3C2410EintSource>().RegisterUnmaskListener(
        [this](uint32_t unmasked) { OnGuestUnmask(unmasked); });
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { ResetDevice(); });
    emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] {
        std::lock_guard<std::mutex> lk(mutex_);
        DriveLineLocked(kPinIdle);
        line_seeded_ = true;
    });
}

void DevEmuKeyboardController::QueueScancode(uint8_t scancode) {
    auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
    std::lock_guard<std::mutex> lk(mutex_);
    queue_.push_back(scancode);
    if (!awaiting_ack_) { PresentLocked(); }
}

/* devemu_wm5 kbdmouse.dll: the IST sub_14D5DF4 takes one byte per interrupt
   (sub_14D5944 -> sub_14D56E4(buf, 1)) and then calls InterruptDone. */
uint8_t DevEmuKeyboardController::Exchange(uint8_t mosi) {
    std::lock_guard<std::mutex> lk(mutex_);
    AcceptHostByteLocked(mosi);
    uint8_t scancode = kNoScancodeResponse;
    if (!queue_.empty()) {
        scancode = queue_.front();
        queue_.pop_front();
    }
    if (line_active_) { awaiting_ack_ = true; }
    DriveLineLocked(kPinIdle);
    line_active_ = false;
    return scancode;
}

void DevEmuKeyboardController::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mutex_);
    w.Write<uint32_t>("queue_count", static_cast<uint32_t>(queue_.size()));
    for (uint8_t b : queue_) { w.Write<uint8_t>("queue", b); }
    w.Write<uint32_t>("cmd_index", cmd_index_);
    w.Write<uint32_t>("cmd_pos", cmd_pos_);
    w.Write<uint8_t>("awaiting_ack", static_cast<uint8_t>(awaiting_ack_));
    w.Write<uint8_t>("line_active", static_cast<uint8_t>(line_active_));
    w.Write<uint8_t>("line_seeded", static_cast<uint8_t>(line_seeded_));
}

void DevEmuKeyboardController::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mutex_);
    queue_.clear();
    uint32_t count = 0;
    r.Read("queue_count", count);
    for (uint32_t i = 0; i < count; ++i) {
        uint8_t b = 0;
        r.Read("queue", b);
        queue_.push_back(b);
    }
    r.Read("cmd_index", cmd_index_);
    r.Read("cmd_pos", cmd_pos_);
    uint8_t awaiting = 0, active = 0, seeded = 0;
    r.Read("awaiting_ack", awaiting);
    r.Read("line_active", active);
    r.Read("line_seeded", seeded);
    if (awaiting > 1u || active > 1u || seeded > 1u || (awaiting != 0u && active != 0u) ||
        (active != 0u && queue_.empty()) ||
        (awaiting == 0u && active == 0u && !queue_.empty())) {
        r.Reject("DevEmuKeyboardController: restored awaiting_ack=%u line_active=%u "
                 "line_seeded=%u with %u queued", awaiting, active, seeded, count);
    }
    awaiting_ack_ = awaiting != 0;
    line_active_  = active   != 0;
    line_seeded_  = seeded   != 0;
}

void DevEmuKeyboardController::ResetDevice() {
    std::lock_guard<std::mutex> lk(mutex_);
    queue_.clear();
    cmd_pos_      = 0;
    cmd_index_    = 0;
    awaiting_ack_ = false;
    line_active_  = false;
    line_seeded_  = false;
}

void DevEmuKeyboardController::DriveLineLocked(bool level) {
    emu_.Get<S3C2410EintSource>().DriveEintPin(kEintNumber, level);
}

void DevEmuKeyboardController::PresentLocked() {
    if (queue_.empty() || line_active_) { return; }
    if (!line_seeded_) {
        DriveLineLocked(kPinIdle);
        line_seeded_ = true;
    }
    DriveLineLocked(kPinDataReady);
    line_active_ = true;
}

/* devemu_wm5 nk.exe OEMInterruptDone sub_800B13FC -> sub_800B1058: SRCPND <- 1 << irq, then
   INTMSK &= ~(1 << irq); OEMInterruptEnable sub_800B1290 -> sub_800B0E54: INTMSK &= ~(1 << irq). */
void DevEmuKeyboardController::OnGuestUnmask(uint32_t unmasked_intmsk) {
    if ((unmasked_intmsk & kEint1IntmskBit) == 0u) { return; }
    std::lock_guard<std::mutex> lk(mutex_);
    awaiting_ack_ = false;
    PresentLocked();
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

REGISTER_SERVICE(DevEmuKeyboardController);
