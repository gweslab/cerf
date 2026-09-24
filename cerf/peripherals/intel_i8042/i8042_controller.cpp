#include "i8042_controller.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/nec_rockhopper/nec_rockhopper_id.h"
#include "../../state/state_stream.h"

#include <cstddef>

namespace {
constexpr uint8_t kStsOutputBufFull = 0x01;
constexpr uint8_t kStsInputBufFull  = 0x02;   /* always 0 here: writes complete synchronously */
constexpr uint8_t kStsOutputBufAux  = 0x20;

constexpr uint8_t kCmdReadModeByte   = 0x20;
constexpr uint8_t kCmdWriteModeByte  = 0x60;
constexpr uint8_t kCmdSelfTest       = 0xAA;   /* -> 0x55 */
constexpr uint8_t kCmdKbdIfaceTest   = 0xAB;   /* -> 0x00 */
constexpr uint8_t kCmdAuxDeviceWrite = 0xD4;   /* next data byte goes to the mouse */

constexpr uint8_t kModeKbdIntEnable = 0x01;
constexpr uint8_t kModeAuxIntEnable = 0x02;
}  // namespace

REGISTER_SERVICE(I8042Controller);

I8042Controller::I8042Controller(CerfEmulator& emu)
    : Service(emu),
      kbd_([] {}),
      mouse_([] {}) {}

bool I8042Controller::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NecRockhopper;
}

int I8042Controller::LoadOutputLocked() {
    if (out_full_) return 0;
    if (!ctrl_resp_.empty()) {
        out_byte_ = ctrl_resp_.front();
        ctrl_resp_.pop_front();
        out_full_ = true;
        out_aux_  = false;
        return 1;
    }
    if (kbd_.HasData()) {
        out_byte_ = kbd_.ReadData();
        out_full_ = true;
        out_aux_  = false;
        return 1;
    }
    if (mouse_.HasData()) {
        out_byte_ = mouse_.ReadData();
        out_full_ = true;
        out_aux_  = true;
        return 2;
    }
    return 0;
}

void I8042Controller::RaiseLoadedIrq(int which) {
    if (which == 1) {
        if ((cmd_byte_ & kModeKbdIntEnable) && kbd_irq_sink_) kbd_irq_sink_();
    } else if (which == 2) {
        if ((cmd_byte_ & kModeAuxIntEnable) && aux_irq_sink_) aux_irq_sink_();
    }
}

void I8042Controller::PumpAndRaise() {
    int which;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        which = LoadOutputLocked();
    }
    RaiseLoadedIrq(which);
}

void I8042Controller::HostKeyboardScancodes(const uint8_t* bytes, size_t n) {
    kbd_.QueueScancodes(bytes, n);
    PumpAndRaise();
}

void I8042Controller::HostMouseMotion(int dx, int dy, uint32_t button_mask) {
    mouse_.QueueMotion(dx, dy, button_mask);
    PumpAndRaise();
}

uint8_t I8042Controller::ReadData() {
    int which;
    uint8_t b;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool had = out_full_;
        b = had ? out_byte_ : 0;
        out_full_ = false;
        which = LoadOutputLocked();
    }
    RaiseLoadedIrq(which);
    return b;
}

uint8_t I8042Controller::ReadStatus() {
    /* Pure status read - no LoadOutputLocked: a status poll must not latch (and
       steal, unraised) a byte the producing PumpAndRaise still has to raise. */
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t s = 0;
    if (out_full_) {
        s |= kStsOutputBufFull;
        if (out_aux_) s |= kStsOutputBufAux;
    }
    (void)kStsInputBufFull;   /* IBF stays clear: WriteData/WriteCommand consume input immediately */
    return s;
}

void I8042Controller::WriteData(uint8_t v) {
    int which;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (pending_) {
            case Pending::kWriteCmdByte:
                cmd_byte_ = v;
                pending_  = Pending::kNone;
                break;
            case Pending::kAuxWrite:
                mouse_.WriteCommand(v);
                pending_ = Pending::kNone;
                break;
            case Pending::kNone:
                kbd_.WriteCommand(v);   /* a byte to port 0x60 with no command prefix = keyboard command */
                break;
        }
        which = LoadOutputLocked();
    }
    RaiseLoadedIrq(which);
}

void I8042Controller::WriteCommand(uint8_t v) {
    int which;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (v) {
            case kCmdReadModeByte:   ctrl_resp_.push_back(cmd_byte_);                  break;
            case kCmdWriteModeByte:  pending_ = Pending::kWriteCmdByte;                break;
            case kCmdSelfTest:       ctrl_resp_.push_back(static_cast<uint8_t>(0x55)); break;
            case kCmdKbdIfaceTest:   ctrl_resp_.push_back(static_cast<uint8_t>(0x00)); break;
            case kCmdAuxDeviceWrite: pending_ = Pending::kAuxWrite;                    break;
            default:
                LOG(Caution, "I8042Controller: unimplemented 8042 command 0x%02X\n", v);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        which = LoadOutputLocked();
    }
    RaiseLoadedIrq(which);
}

void I8042Controller::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("cmd_byte", cmd_byte_);
    w.Write("pending", static_cast<uint8_t>(pending_));
    w.Write("out_byte", out_byte_);
    w.Write<uint8_t>("out_full", out_full_ ? 1u : 0u);
    w.Write<uint8_t>("out_aux", out_aux_ ? 1u : 0u);
    w.Write<uint32_t>("ctrl_resp_count", static_cast<uint32_t>(ctrl_resp_.size()));
    for (uint8_t b : ctrl_resp_) w.Write("ctrl_resp", b);
    kbd_.SaveState(w);
    mouse_.SaveState(w);
}

void I8042Controller::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("cmd_byte", cmd_byte_);
    uint8_t p = 0; r.Read("pending", p); pending_ = static_cast<Pending>(p);
    r.Read("out_byte", out_byte_);
    uint8_t full = 0, aux = 0;
    r.Read("out_full", full); r.Read("out_aux", aux);
    out_full_ = (full != 0);
    out_aux_  = (aux != 0);
    uint32_t n = 0; r.Read("ctrl_resp_count", n);
    ctrl_resp_.clear();
    for (uint32_t i = 0; i < n; ++i) { uint8_t b = 0; r.Read("ctrl_resp", b); ctrl_resp_.push_back(b); }
    kbd_.RestoreState(r);
    mouse_.RestoreState(r);
}
