#include "odo_arm720_touch_sound.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/irq_controller.h"

#include "odo_arm720_audio_player.h"
#include "odo_arm720_board_intc.h"

#include <chrono>
#include <cstdint>
#include <mutex>

namespace {

/* TCHAUD.H + ODOREGS.H + P2.H bit definitions. */
constexpr uint32_t kSlotIoAdcCntr    = 0x00u;
constexpr uint32_t kSlotIoAdcStr     = 0x04u;
constexpr uint32_t kSlotUcbCntr      = 0x08u;
constexpr uint32_t kSlotUcbStr       = 0x0Cu;
constexpr uint32_t kSlotUcbRegister  = 0x10u;
constexpr uint32_t kSlotIoSoundCntr  = 0x14u;
constexpr uint32_t kSlotIoSoundStr   = 0x18u;
constexpr uint32_t kSlotIntrMask     = 0x1Cu;

constexpr uint16_t kIoAdcStrW1cMask    = (1u << 4) | (1u << 3) | (1u << 2);
constexpr uint16_t kUcbStrW1cMask      = (1u << 0);
constexpr uint16_t kIoSoundStrW1cMask  = (1u << 15) | (1u << 14)
                                       | (1u << 13) | (1u << 12);

constexpr uint16_t kIoSoundCntrPlaybackEn = (1u << 14);

/* ioAdcStr / intrMask bits (P2.H:395-405). */
constexpr uint16_t kPenIntr           = 0x0010u;  /* ioAdcStr bit 4 */
constexpr uint16_t kPenTimingIntr     = 0x0004u;  /* ioAdcStr bit 2 */
constexpr uint16_t kUcbIntr           = 0x0008u;  /* ioAdcStr bit 3 */
constexpr uint16_t kRegIntr           = 0x0001u;  /* ucbStr   bit 0 */

constexpr uint16_t kRegIntrMask        = 0x0001u;
constexpr uint16_t kSoundIntrMask      = 0x0002u;
constexpr uint16_t kPenTimingIntrMask  = 0x0004u;
constexpr uint16_t kUcbIntrMask        = 0x0008u;
constexpr uint16_t kPenIntrMask        = 0x0010u;

/* ioAdcCntr bits (TCHAUD.H:81-83 + P2.H:426-429). */
constexpr uint16_t kIoAdcCntrDoSample     = 0x4000u; /* bit 14 */
constexpr uint16_t kIoAdcCntrAdcSelY      = 0x0800u; /* bit 11 */
constexpr uint16_t kIoAdcCntrPenTimingEn  = 0x0400u; /* bit 10 */
/* P2.H:421 — Odo ARM uses TOUCH_AUDIO_CRYSTAL (proven by TCHPDD.CPP:
   1260 CRYSTAL-branch reading UCB reg 10 fires in our log), so the
   12-bit sample mask applies, not the UCB1100 10-bit one. */
constexpr uint16_t kTouchSampleValid      = 0x0FFFu;

/* TCHMDD.C:91 X_SCALE_FACTOR — GWES divides calibrated coord by 4
   to get screen pixel; with v_Calibrated=FALSE the calibration is
   identity so raw_x = pixel_x * 4 is what reaches GWES. */
constexpr int     kCalScaleFactor          = 4;

/* P2.H:403 penState — set in ucbRegister bit 12 = PEN UP. */
constexpr uint16_t kUcbRegisterPenState   = 0x1000u;

}  /* namespace */

REGISTER_SERVICE(OdoArm720TouchSound);

OdoArm720TouchSound::~OdoArm720TouchSound() {
    shutdown_.store(true, std::memory_order_release);
    pen_timer_enabled_.store(true, std::memory_order_release);
    pen_timer_cv_.notify_all();
    if (pen_timer_thread_.joinable()) pen_timer_thread_.join();
}

bool OdoArm720TouchSound::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetBoard() == Board::OdoArm720;
}

void OdoArm720TouchSound::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    pen_timer_thread_ = std::thread([this] { PenTimerMain(); });
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

void OdoArm720TouchSound::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
#if CERF_DEV_MODE
    LOG(Periph, "Odo TOUCH_SOUND write %s (+0x%02X) = 0x%04X\n",
        SlotName(off), off, value);
#endif

    if (off == kSlotIoAdcCntr) {
        bool need_recompute   = false;
        bool timer_enable_now = false;
        bool timer_disable    = false;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            const bool old_timing = (io_adc_cntr_ & kIoAdcCntrPenTimingEn) != 0;
            io_adc_cntr_ = value;
            DoAdcSampleLocked(value);
            const bool new_timing = (value & kIoAdcCntrPenTimingEn) != 0;
            if (new_timing && !old_timing) timer_enable_now = true;
            if (!new_timing && old_timing) timer_disable    = true;
            need_recompute = true;
        }
        if (timer_enable_now) {
            pen_timer_enabled_.store(true, std::memory_order_release);
            pen_timer_cv_.notify_all();
        }
        if (timer_disable) {
            pen_timer_enabled_.store(false, std::memory_order_release);
        }
        if (need_recompute) RecomputeTouchAudioIrq();
        return;
    }

    if (off == kSlotUcbCntr) {
        std::lock_guard<std::mutex> lk(state_mutex_);
        ucb_cntr_ = value;
        return;
    }
    if (off == kSlotUcbRegister) {
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            const uint8_t  reg     = static_cast<uint8_t>(ucb_cntr_ & 0xFu);
            const bool     is_write = (ucb_cntr_ & 0x10u) != 0u;
            if (is_write) {
                ucb_regs_[reg] = value;
                ucb_register_  = value;
            } else {
                uint16_t v = ucb_regs_[reg];
                /* UCB register 10: TCHPDD.CPP:1258-1270 spins on
                   bits 10/11 (touch + ADC cal complete) after
                   writing start bits — auto-set both so polls
                   exit instantly. */
                if (reg == 0x0A) v |= 0x0C00u;
                /* UCB register 9: kernel reads to check pen state
                   (ARMINT.C:142). Bit 12 set = PEN UP per P2.H:403. */
                if (reg == 0x09) {
                    if (pen_down_.load(std::memory_order_acquire)) {
                        v &= static_cast<uint16_t>(~kUcbRegisterPenState);
                    } else {
                        v |= kUcbRegisterPenState;
                    }
                }
                ucb_register_ = v;
            }
            ucb_str_ |= kRegIntr;
        }
        RecomputeTouchAudioIrq();
        return;
    }

    if (off == kSlotIoSoundCntr) {
        uint16_t old_value;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            old_value      = io_sound_cntr_;
            io_sound_cntr_ = value;
        }
        NotifyAudioControlChange(old_value, value);
        return;
    }

    if (off == kSlotIntrMask) {
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            intr_mask_ = value;
        }
        RecomputeTouchAudioIrq();
        return;
    }

    if (off == kSlotIoAdcStr) {
        if ((value & ~kIoAdcStrW1cMask) != 0) {
            LOG(Caution, "Odo TOUCH_SOUND: ioAdcStr write = 0x%04X "
                    "has bits outside W1C mask 0x%04X (pen/UCB/"
                    "pen-tmg).\n", value, kIoAdcStrW1cMask);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            io_adc_str_ &= static_cast<uint16_t>(~(value & kIoAdcStrW1cMask));
        }
        RecomputeTouchAudioIrq();
        return;
    }
    if (off == kSlotUcbStr) {
        if ((value & ~kUcbStrW1cMask) != 0) {
            LOG(Caution, "Odo TOUCH_SOUND: ucbStr write = 0x%04X "
                    "has bits outside W1C mask 0x%04X "
                    "(ucbStrRegIntr).\n", value, kUcbStrW1cMask);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            ucb_str_ &= static_cast<uint16_t>(~(value & kUcbStrW1cMask));
        }
        RecomputeTouchAudioIrq();
        return;
    }
    if (off == kSlotIoSoundStr) {
        if ((value & ~kIoSoundStrW1cMask) != 0) {
            LOG(Caution, "Odo TOUCH_SOUND: ioSoundStr write = 0x%04X "
                    "has bits outside W1C mask 0x%04X (record/"
                    "playback intrs).\n", value, kIoSoundStrW1cMask);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            io_sound_str_ &= static_cast<uint16_t>(~(value & kIoSoundStrW1cMask));
        }
        RecomputeTouchAudioIrq();
        return;
    }

    HaltUnsupportedAccess("WriteHalf", addr, value);
}

uint32_t OdoArm720TouchSound::ReadWord(uint32_t addr) {
    return static_cast<uint32_t>(ReadHalf(addr));
}

void OdoArm720TouchSound::WriteWord(uint32_t addr, uint32_t value) {
    if ((value & 0xFFFF0000u) != 0u) {
        LOG(Caution, "Odo TOUCH_SOUND: WriteWord 0x%08X = 0x%08X has "
                "non-zero high 16 bits in PAD region (TCHAUD.H "
                "USHORT+PAD layout).\n", addr, value);
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

bool OdoArm720TouchSound::PlaybackEnabled() const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return (io_sound_cntr_ & kIoSoundCntrPlaybackEn) != 0;
}

bool OdoArm720TouchSound::SoundIntrEnabled() const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return (intr_mask_ & kSoundIntrMask) != 0;
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
        io_adc_str_ |= kUcbIntr;
    }
    pen_down_.store(true, std::memory_order_release);
    RecomputeTouchAudioIrq();
}

void OdoArm720TouchSound::OnPenMove(int host_x, int host_y) {
    if (!pen_down_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(state_mutex_);
    adc_x_ = HostPixelToRaw(host_x);
    adc_y_ = HostPixelToRaw(host_y);
}

void OdoArm720TouchSound::OnPenUp() {
    pen_down_.store(false, std::memory_order_release);
}

void OdoArm720TouchSound::PenTimerMain() {
    while (!shutdown_.load(std::memory_order_acquire)) {
        {
            std::unique_lock<std::mutex> lk(pen_timer_cv_mtx_);
            pen_timer_cv_.wait(lk, [this] {
                return shutdown_.load(std::memory_order_acquire)
                    || pen_timer_enabled_.load(std::memory_order_acquire);
            });
        }
        if (shutdown_.load(std::memory_order_acquire)) break;

        while (pen_timer_enabled_.load(std::memory_order_acquire)
               && !shutdown_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            if (!pen_timer_enabled_.load(std::memory_order_acquire)) break;
            {
                std::lock_guard<std::mutex> lk(state_mutex_);
                io_adc_str_ |= kPenTimingIntr;
            }
            RecomputeTouchAudioIrq();
        }
    }
}
