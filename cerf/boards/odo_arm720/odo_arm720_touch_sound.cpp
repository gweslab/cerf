#include "odo_arm720_touch_sound.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../peripherals/philips_ucb1200/ucb1x00_codec.h"
#include "../../state/state_stream.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/irq_controller.h"

#include "odo_arm720_audio_player.h"
#include "odo_arm720_board_intc.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kSlotIoAdcCntr    = 0x00u;
constexpr uint32_t kSlotIoAdcStr     = 0x04u;
constexpr uint32_t kSlotUcbCntr      = 0x08u;
constexpr uint32_t kSlotUcbStr       = 0x0Cu;
constexpr uint32_t kSlotUcbRegister  = 0x10u;
constexpr uint32_t kSlotIoSoundCntr  = 0x14u;
constexpr uint32_t kSlotIoSoundStr   = 0x18u;
constexpr uint32_t kSlotIntrMask     = 0x1Cu;

constexpr uint16_t kIoAdcStrW1cMask    = (1u << 4) | (1u << 2);
constexpr uint16_t kUcbStrW1cMask      = (1u << 0);
constexpr uint16_t kIoSoundStrW1cMask  = (1u << 15) | (1u << 14)
                                       | (1u << 13) | (1u << 12);

constexpr uint16_t kIoSoundCntrPlaybackEn      = (1u << 14);

constexpr uint16_t kPenIntr           = 0x0010u;
constexpr uint16_t kPenTimingIntr     = 0x0004u;
constexpr uint16_t kUcbIntr           = 0x0008u;
constexpr uint16_t kRegIntr           = 0x0001u;

constexpr uint16_t kRegIntrMask        = 0x0001u;
constexpr uint16_t kSoundIntrMask      = 0x0002u;
constexpr uint16_t kPenTimingIntrMask  = 0x0004u;
constexpr uint16_t kUcbIntrMask        = 0x0008u;
constexpr uint16_t kPenIntrMask        = 0x0010u;

constexpr uint16_t kIoAdcCntrDoSample     = 0x4000u;
constexpr uint16_t kIoAdcCntrAdcSelY      = 0x0800u;
constexpr uint16_t kIoAdcCntrPenTimingEn  = 0x0400u;
constexpr uint16_t kTouchSampleValid      = 0x0FFFu;

constexpr uint16_t kUcbCntrRegMask = 0x000Fu;
constexpr uint16_t kUcbCntrWrite   = 0x0010u;

constexpr uint16_t kIoAdcCntrModelled =
    kIoAdcCntrDoSample | kIoAdcCntrAdcSelY | kIoAdcCntrPenTimingEn;
constexpr uint16_t kUcbCntrModelled  = kUcbCntrRegMask | kUcbCntrWrite;
constexpr uint16_t kIntrMaskModelled = kRegIntrMask | kSoundIntrMask | kPenTimingIntrMask |
                                       kUcbIntrMask | kPenIntrMask;

constexpr int     kCalScaleFactor          = 4;

}

REGISTER_SERVICE(OdoArm720TouchSound);

bool OdoArm720TouchSound::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Odo;
}

void OdoArm720TouchSound::OnReady() {
    codec_ = &emu_.Get<Ucb1x00Codec>();
    pen_timer_.Attach();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetLine(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void OdoArm720TouchSound::ResetLine() {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        io_adc_cntr_   = 0u;
        io_adc_str_    = 0u;
        ucb_cntr_      = 0u;
        ucb_str_       = 0u;
        ucb_register_  = 0u;
        io_sound_cntr_ = 0u;
        io_sound_str_  = 0u;
        intr_mask_     = 0u;
    }
    pen_timer_.SetEnabled(false);
    RecomputeTouchAudioIrq();
}

const char* OdoArm720TouchSound::SlotName(uint32_t off) {
    switch (off) {
        case kSlotIoAdcCntr:    return "ioAdcCntr";
        case kSlotIoAdcStr:     return "ioAdcStr";
        case kSlotUcbCntr:      return "ucbCntr";
        case kSlotUcbStr:       return "ucbStr";
        case kSlotUcbRegister:  return "ucbRegister";
        case kSlotIoSoundCntr:  return "ioSoundCntr";
        case kSlotIoSoundStr:   return "ioSoundStr";
        case kSlotIntrMask:     return "intrMask";
        default:                return "(unknown)";
    }
}

uint16_t OdoArm720TouchSound::SlotRefLocked(uint32_t off, uint16_t*& out_ref) {
    switch (off) {
        case kSlotIoAdcCntr:    out_ref = &io_adc_cntr_;   break;
        case kSlotIoAdcStr:     out_ref = &io_adc_str_;    break;
        case kSlotUcbCntr:      out_ref = &ucb_cntr_;      break;
        case kSlotUcbStr:       out_ref = &ucb_str_;       break;
        case kSlotUcbRegister:  out_ref = &ucb_register_;  break;
        case kSlotIoSoundCntr:  out_ref = &io_sound_cntr_; break;
        case kSlotIoSoundStr:   out_ref = &io_sound_str_;  break;
        case kSlotIntrMask:     out_ref = &intr_mask_;     break;
        default:                out_ref = nullptr;         return 0;
    }
    return *out_ref;
}

bool OdoArm720TouchSound::ShouldTouchAudioBeLiveLocked() const {
    const uint16_t pen     = io_adc_str_ & kPenIntr        & intr_mask_ & kPenIntrMask;
    const uint16_t pen_t   = io_adc_str_ & kPenTimingIntr  & intr_mask_ & kPenTimingIntrMask;
    const uint16_t ucb     = io_adc_str_ & kUcbIntr        & intr_mask_ & kUcbIntrMask;
    const uint16_t reg     = ucb_str_    & kRegIntr        & intr_mask_ & kRegIntrMask;
    const uint16_t snd     = (io_sound_str_ & kIoSoundStrW1cMask)
                           & ((intr_mask_ & kSoundIntrMask) ? 0xFFFFu : 0u);
    return (pen | pen_t | ucb | reg | snd) != 0u;
}

void OdoArm720TouchSound::RecomputeTouchAudioIrq() {
    bool live;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        live = ShouldTouchAudioBeLiveLocked();
    }
    auto& intc = emu_.Get<IrqController>();
    if (live) intc.AssertIrq(kSourceTouchAudioAdcIntr);
    else      intc.DeAssertIrq(kSourceTouchAudioAdcIntr);
}

uint16_t OdoArm720TouchSound::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint16_t  value = 0;
    uint16_t* ref   = nullptr;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        value = SlotRefLocked(off, ref);
    }
    if (ref == nullptr) HaltUnsupportedAccess("ReadHalf", addr, 0);
#if CERF_DEV_MODE
    LOG(Periph, "Odo TOUCH_SOUND read  %s (+0x%02X) -> 0x%04X\n",
        SlotName(off), off, value);
#endif
    return value;
}

void OdoArm720TouchSound::DoAdcSampleLocked(uint16_t io_adc_cntr_write) {
    if ((io_adc_cntr_write & kIoAdcCntrDoSample) == 0) return;
    const bool want_y = (io_adc_cntr_write & kIoAdcCntrAdcSelY) != 0;
    const uint16_t sample = want_y ? adc_y_ : adc_x_;
    io_adc_cntr_ = static_cast<uint16_t>(
        (io_adc_cntr_write & ~kTouchSampleValid) |
        (sample & kTouchSampleValid));
    io_adc_str_ |= kPenIntr;
}

void OdoArm720TouchSound::TransferUcbRegister(uint16_t value) {
    uint16_t cntr;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        cntr = ucb_cntr_;
    }
    const uint8_t reg    = static_cast<uint8_t>(cntr & kUcbCntrRegMask);
    uint16_t      result = value;
    if (cntr & kUcbCntrWrite) codec_->WriteReg(reg, value);
    else                      result = codec_->ReadReg(reg);
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        ucb_register_ = result;
        ucb_str_     |= kRegIntr;
    }
    RecomputeTouchAudioIrq();
}

void OdoArm720TouchSound::CheckModelledBits(uint32_t off, uint16_t value,
                                            uint16_t modelled) {
    if ((value & ~modelled) != 0u) {
        emu_.Get<Fatal>().Die(
            "odo touch: %s write 0x%04X sets bits 0x%04X outside the modelled 0x%04X",
            SlotName(off), value, static_cast<uint16_t>(value & ~modelled), modelled);
    }
}

void OdoArm720TouchSound::WriteStatusW1c(uint32_t addr, uint16_t value,
                                         uint16_t w1c_mask, uint16_t& reg) {
    if ((value & ~w1c_mask) != 0) {
        emu_.Get<Fatal>().Die(
            "odo touch: %s write 0x%04X has bits outside the write-one-to-clear "
            "mask 0x%04X", SlotName(addr - MmioBase()), value, w1c_mask);
    }
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        reg &= static_cast<uint16_t>(~value);
    }
    RecomputeTouchAudioIrq();
}

void OdoArm720TouchSound::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
#if CERF_DEV_MODE
    LOG(Periph, "Odo TOUCH_SOUND write %s (+0x%02X) = 0x%04X\n",
        SlotName(off), off, value);
#endif

    switch (off) {
        case kSlotIoAdcCntr:
            CheckModelledBits(off, value, kIoAdcCntrModelled);
            {
                std::lock_guard<std::mutex> lk(state_mutex_);
                io_adc_cntr_ = value;
                DoAdcSampleLocked(value);
            }
            pen_timer_.SetEnabled((value & kIoAdcCntrPenTimingEn) != 0);
            RecomputeTouchAudioIrq();
            return;
        case kSlotUcbCntr: {
            CheckModelledBits(off, value, kUcbCntrModelled);
            std::lock_guard<std::mutex> lk(state_mutex_);
            ucb_cntr_ = value;
            return;
        }
        case kSlotUcbRegister:
            TransferUcbRegister(value);
            return;
        case kSlotIoSoundCntr: {
            CheckModelledBits(off, value, kIoSoundCntrPlaybackEn);
            uint16_t old_value;
            {
                std::lock_guard<std::mutex> lk(state_mutex_);
                old_value      = io_sound_cntr_;
                io_sound_cntr_ = value;
            }
            NotifyAudioControlChange(old_value, value);
            return;
        }
        case kSlotIntrMask:
            CheckModelledBits(off, value, kIntrMaskModelled);
            {
                std::lock_guard<std::mutex> lk(state_mutex_);
                intr_mask_ = value;
            }
            RecomputeTouchAudioIrq();
            return;
        case kSlotIoAdcStr:
            WriteStatusW1c(addr, value, kIoAdcStrW1cMask, io_adc_str_);
            if ((value & kPenTimingIntr) != 0u) pen_timer_.OnStatusCleared();
            return;
        case kSlotUcbStr:
            WriteStatusW1c(addr, value, kUcbStrW1cMask, ucb_str_);
            return;
        case kSlotIoSoundStr:
            WriteStatusW1c(addr, value, kIoSoundStrW1cMask, io_sound_str_);
            return;
        default:
            HaltUnsupportedAccess("WriteHalf", addr, value);
    }
}

uint32_t OdoArm720TouchSound::ReadWord(uint32_t addr) {
    return static_cast<uint32_t>(ReadHalf(addr));
}

void OdoArm720TouchSound::WriteWord(uint32_t addr, uint32_t value) {
    if ((value & 0xFFFF0000u) != 0u) {
        LOG(Caution, "Odo TOUCH_SOUND: WriteWord 0x%08X = 0x%08X has "
                "non-zero high 16 bits in the PAD region of a "
                "16-bit register.\n", addr, value);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    WriteHalf(addr, static_cast<uint16_t>(value & 0xFFFFu));
}

void OdoArm720TouchSound::NotifyAudioControlChange(uint16_t old_value,
                                                   uint16_t new_value) {
    const bool old_play = (old_value & kIoSoundCntrPlaybackEn) != 0;
    const bool new_play = (new_value & kIoSoundCntrPlaybackEn) != 0;
    if (old_play != new_play) {
        emu_.Get<OdoArm720AudioPlayer>().SetPlaybackEnabled(new_play);
    }
}

bool OdoArm720TouchSound::RaiseSoundStrBits(uint16_t bits) {
    bool already;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        already = (io_sound_str_ & bits) != 0;
        io_sound_str_ |= bits;
    }
    RecomputeTouchAudioIrq();
    return already;
}

uint16_t OdoArm720TouchSound::HostPixelToRaw(int host_v) {
    if (host_v < 0) host_v = 0;
    const int raw = host_v * kCalScaleFactor;
    if (raw > static_cast<int>(kTouchSampleValid)) {
        return kTouchSampleValid;
    }
    return static_cast<uint16_t>(raw);
}

void OdoArm720TouchSound::OnPenDown(int host_x, int host_y) {
    const uint16_t x12 = HostPixelToRaw(host_x);
    const uint16_t y12 = HostPixelToRaw(host_y);
    LOG(Periph, "Odo TOUCH: PenDown host=(%d,%d) raw=(0x%03X,0x%03X)\n",
        host_x, host_y, x12, y12);
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        adc_x_ = x12;
        adc_y_ = y12;
    }
    codec_->SetTouchPressed(true);
}

void OdoArm720TouchSound::OnPenMove(int host_x, int host_y) {
    if (!codec_->PenDown()) return;
    std::lock_guard<std::mutex> lk(state_mutex_);
    adc_x_ = HostPixelToRaw(host_x);
    adc_y_ = HostPixelToRaw(host_y);
}

void OdoArm720TouchSound::OnPenUp() {
    codec_->SetTouchPressed(false);
}

void OdoArm720TouchSound::SetUcbIrqOut(bool asserted) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (asserted) io_adc_str_ |= kUcbIntr;
        else          io_adc_str_ &= static_cast<uint16_t>(~kUcbIntr);
    }
    RecomputeTouchAudioIrq();
}

void OdoArm720TouchSound::OnPenTimingPeriod() {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        io_adc_str_ |= kPenTimingIntr;
    }
    RecomputeTouchAudioIrq();
}

bool OdoArm720TouchSound::PenTimingPending() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return (io_adc_str_ & kPenTimingIntr) != 0u;
}

void OdoArm720TouchSound::SaveState(StateWriter& w) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("io_adc_cntr", io_adc_cntr_);  w.Write("io_adc_str", io_adc_str_);
        w.Write("ucb_cntr", ucb_cntr_);     w.Write("ucb_str", ucb_str_);  w.Write("ucb_register", ucb_register_);
        w.Write("io_sound_cntr", io_sound_cntr_); w.Write("io_sound_str", io_sound_str_);
        w.Write("intr_mask", intr_mask_);
        w.Write("adc_x", adc_x_);  w.Write("adc_y", adc_y_);
    }
    codec_->SaveState(w);
    pen_timer_.SaveState(w);
    emu_.Get<OdoArm720AudioPlayer>().SaveState(w);
}

void OdoArm720TouchSound::RestoreState(StateReader& r) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("io_adc_cntr", io_adc_cntr_);  r.Read("io_adc_str", io_adc_str_);
        r.Read("ucb_cntr", ucb_cntr_);     r.Read("ucb_str", ucb_str_);  r.Read("ucb_register", ucb_register_);
        r.Read("io_sound_cntr", io_sound_cntr_); r.Read("io_sound_str", io_sound_str_);
        r.Read("intr_mask", intr_mask_);
        r.Read("adc_x", adc_x_);  r.Read("adc_y", adc_y_);
    }
    codec_->RestoreState(r);
    pen_timer_.RestoreState(r);
    emu_.Get<OdoArm720AudioPlayer>().RestoreState(r);
}

void OdoArm720TouchSound::PostRestore() {
    emu_.Get<OdoArm720AudioPlayer>().PostRestore();
}
