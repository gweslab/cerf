#include "pr31x00_lcd.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "pr31x00_intc.h"

#include <chrono>
#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C00028u;

enum RegIndex : uint32_t {
    kCtl1  = 0,   /* $028 R/W */
    kCtl2  = 1,   /* $02C write-only */
    kCtl3  = 2,   /* $030 write-only */
    kCtl4  = 3,   /* $034 write-only */
    kCtl5  = 4,   /* $038 write-only */
    kCtl6  = 5,   /* $03C write-only */
    kCtl7  = 6,   /* $040 write-only */
    kCtl8  = 7,   /* $044 write-only */
    kCtl9  = 8,   /* $048 write-only */
    kCtl10 = 9,   /* $04C write-only */
    kCtl11 = 10,  /* $050 write-only */
    kCtl12 = 11,  /* $054 write-only */
    kCtl13 = 12,  /* $058 write-only */
    kCtl14 = 13,  /* $05C write-only */
};

/* Video Control 1 (§17.4.1): LINECNT[9:0]<31:22> R, LOADDLY<21>, BAUDVAL[4:0]<20:16>,
   VIDDONEVAL[6:0]<15:9>, ENFREEZEFRAME<8>, BITSEL[1:0]<7:6>, DISPSPLIT<5>, DISP8<4>,
   DFMODE<3>, INVVID<2>, DISPON<1>, ENVID<0>. */
constexpr uint32_t kCtl1Writable = 0x003FFFFFu;
constexpr uint32_t kEnVid        = 1u << 0;
constexpr uint32_t kInvVid       = 1u << 2;
constexpr uint32_t kDisp8        = 1u << 4;
constexpr uint32_t kDispSplit    = 1u << 5;
constexpr uint32_t kBitSelShift  = 6;

/* BITSEL[1:0] (§17.4.1): $0 monochrome, $1 2-bit gray, $2 4-bit gray, $3 8-bit color. */
constexpr uint32_t kBitSel8BitColor = 3u;

/* Video Control 2 (§17.4.2): VIDRATE[9:0]<31:22>, HORZVAL[8:0]<20:12>, LINEVAL[9:0]<9:0>.
   HORZVAL = HorzSize/4 - 1, or HorzSize/8 - 1 for an 8-bit non-split LCD (§17.3.3).
   LINEVAL = lines - 1 for a non-split LCD. */
constexpr uint32_t kHorzValShift = 12;
constexpr uint32_t kHorzValMask  = 0x1FFu;
constexpr uint32_t kLineValMask  = 0x3FFu;
constexpr uint32_t kVidRateShift = 22;
constexpr uint32_t kVidRateMask  = 0x3FFu;

/* BAUDVAL[4:0] (§17.4.1) divides the video master clock into the CP clock:
   CP Rate = f_VIDCLK / (BAUDVAL*2 + 2). Line Rate = CP Rate / (VIDRATE+1) and
   Frame Rate = Line Rate / (LINEVAL+1) (§17.4.2). */
constexpr uint32_t kBaudValShift = 16;
constexpr uint32_t kBaudValMask  = 0x1Fu;

/* f_VIDCLK = f_XHFREE / 2^VIDRF = f_IN * 4 with VIDRF reset to 0 (Table 6.3.1);
   nk.exe sub_9F434078 divides 36864000 to derive VIDRATE, pinning f_IN at
   9.216 MHz on this board. */
constexpr uint64_t kVidClkHz = 36864000u;

/* LCDINT, Interrupt Status 1 bit 31: "Issues an interrupt at the end of each
   video frame" (§8.3.1). Status set 0 == Interrupt Status 1. */
constexpr uint32_t kLcdIntSet = 0;
constexpr uint32_t kLcdInt    = 1u << 31;

/* Video Control 3 (§17.4.3): VIDBANK[31:20] concatenated with VIDBASEHI[19:4] form the
   address video data is fetched from; bits 3-0 reserved. */
constexpr uint32_t kFbAddrMask = 0xFFFFFFF0u;

/* Video Control 4 (§17.4.4): DFVAL[7:0]<31:24>, FRAMEMASKVAL[3:0]<23:20>,
   VIDBASELO<19:4>; bits 3-0 reserved. VIDBASELO starts the lower address counter,
   which feeds FIFOLO - unused on a non-split display (§17.3.6). DFVAL scales the DF
   toggle rate and only reaches the DF pin while DFMODE is set (§17.4.1). */
constexpr uint32_t kCtl4FrameMaskVal = 0x00F00000u;

/* REDSEL (§17.4.5) and GREENSEL (§17.4.6) expand 8-bit color's 3-bit red and green
   channels; BITSEL 8-bit color is rejected above, so neither table reaches the panel. */

/* PATn_m spread a shade's duty cycle over n frames (§17.4.8-§17.4.14), and
   Pr31x00LcdRenderer draws the steady-state shade the RECOMMENDED PATTERN rows realize:
   any other pattern renders at a gray the guest did not ask for. Line 0 is the high
   nibble. */
constexpr uint32_t kPat2_3Recommended = 0x000007DAu;   /* §17.4.8  CTL8  */
constexpr uint32_t kPat3_4Pat2_4Recommended = 0x7DBEA5A5u; /* §17.4.9  CTL9  */
constexpr uint32_t kPat4_5Recommended = 0x0007DFBEu;   /* §17.4.10 CTL10 */
constexpr uint32_t kPat3_5Recommended = 0x0007A5ADu;   /* §17.4.11 CTL11 */
constexpr uint32_t kPat6_7Recommended = 0x0FBFDFE7u;   /* §17.4.12 CTL12 */
constexpr uint32_t kPat5_7Recommended = 0x07B5ADEFu;   /* §17.4.13 CTL13 */
constexpr uint32_t kPat4_7Recommended = 0x0B9DC663u;   /* §17.4.14 CTL14 */

/* Reserved bits: §17.4.2 CTL2 <21> and <11:10>; §17.4.3 CTL3 <3:0>; §17.4.4 CTL4 <3:0>;
   §17.4.7 CTL7 <31:16>; §17.4.8 CTL8 <31:12>; §17.4.10 CTL10 and §17.4.11 CTL11 <31:20>;
   §17.4.12 CTL12, §17.4.13 CTL13 and §17.4.14 CTL14 <31:28>. */
constexpr uint32_t kCtl2Reserved  = 0x00200C00u;
constexpr uint32_t kCtl3Reserved  = 0x0000000Fu;
constexpr uint32_t kCtl4Reserved  = 0x0000000Fu;
constexpr uint32_t kCtl7Reserved  = 0xFFFF0000u;
constexpr uint32_t kCtl8Reserved  = 0xFFFFF000u;
constexpr uint32_t kPat20Reserved = 0xFFF00000u;
constexpr uint32_t kPat28Reserved = 0xF0000000u;

}  /* namespace */

bool Pr31x00Lcd::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00Lcd::OnReady() {
    intc_ = &emu_.Get<Pr31x00Intc>();
    emu_.Get<PeripheralDispatcher>().Register(this);
    worker_ = std::thread([this] { WorkerLoop(); });
}

void Pr31x00Lcd::PublishFrameTiming() {
    const uint32_t baudval = (reg_[kCtl1] >> kBaudValShift) & kBaudValMask;
    const uint32_t vidrate = (reg_[kCtl2] >> kVidRateShift) & kVidRateMask;
    const uint32_t lineval = reg_[kCtl2] & kLineValMask;

    const uint64_t cp_divisor    = static_cast<uint64_t>(baudval) * 2u + 2u;
    const uint64_t frame_divisor = cp_divisor * (vidrate + 1u) * (lineval + 1u);

    frame_period_ns_.store(frame_divisor * 1000000000ull / kVidClkHz,
                           std::memory_order_release);
    envid_.store((reg_[kCtl1] & kEnVid) != 0u, std::memory_order_release);

    std::lock_guard<std::mutex> g(cv_mtx_);
    cv_.notify_all();
}

void Pr31x00Lcd::StopWorker() {
    if (!worker_.joinable()) return;
    stop_.store(true);
    { std::lock_guard<std::mutex> g(cv_mtx_); }
    cv_.notify_all();
    worker_.join();
}

void Pr31x00Lcd::WorkerLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    while (!stop_.load()) {
        const uint64_t period = frame_period_ns_.load(std::memory_order_acquire);
        const bool     on     = envid_.load(std::memory_order_acquire);

        if (on && period) {
            auto frozen = freeze.WorkerSection();
            intc_->SetPending(kLcdIntSet, kLcdInt);
        }

        std::unique_lock<std::mutex> lk(cv_mtx_);
        if (on && period) {
            cv_.wait_for(lk, std::chrono::nanoseconds(period),
                         [this] { return stop_.load(); });
        } else {
            /* ENVID gates the frame clock, so an idle wait must also break when
               the guest enables the video logic - PublishFrameTiming stores
               envid_ before it notifies. */
            cv_.wait(lk, [this] {
                return stop_.load() || envid_.load(std::memory_order_acquire);
            });
        }
    }
}

bool Pr31x00Lcd::IsEnabled() const { return (reg_[kCtl1] & kEnVid) != 0; }
bool Pr31x00Lcd::IsInverted() const { return (reg_[kCtl1] & kInvVid) != 0; }

uint32_t Pr31x00Lcd::GetFbPa() const { return reg_[kCtl3] & kFbAddrMask; }

uint32_t Pr31x00Lcd::GetGuestW() const {
    const uint32_t horzval = (reg_[kCtl2] >> kHorzValShift) & kHorzValMask;
    return (horzval + 1u) * ((reg_[kCtl1] & kDisp8) ? 8u : 4u);
}

uint32_t Pr31x00Lcd::GetGuestH() const { return (reg_[kCtl2] & kLineValMask) + 1u; }

uint32_t Pr31x00Lcd::GetBitsPerPixel() const {
    return 1u << ((reg_[kCtl1] >> kBitSelShift) & 3u);
}

uint32_t Pr31x00Lcd::ShadeFor(uint32_t raw) const {
    const uint32_t bpp = GetBitsPerPixel();
    uint32_t vdat;
    if (bpp == 2u) {
        vdat = (reg_[kCtl7] >> (4u * raw)) & 0xFu;
    } else if (bpp == 1u) {
        vdat = raw ? 0xFu : 0u;
    } else {
        vdat = raw;
    }
    /* VDAT is the count of frames a pixel is turned ON, not its brightness, so a
       driven pixel is dark (§17.3.7, PDF p.346); INVVID then inverts VDAT[3:0]
       (§17.4.1, PDF p.352). Drop either flip and the panel renders inverted: the
       OAL sets INVVID and BLUESEL $FB60 maps raw index 3 to VDAT $F, ddi.dll white. */
    const uint32_t on_duty = IsInverted() ? (0xFu - vdat) : vdat;
    return 0xFu - on_duty;
}

uint32_t Pr31x00Lcd::ReadWord(uint32_t addr) {
    switch ((addr - kBase) / 4u) {
        case kCtl1: return reg_[kCtl1];
        /* $034 is write-only (§17.4.4) but latches: nk.exe sub_91002514
           read-modify-writes it (v0[13] &= 0xFF0FFFFF). */
        case kCtl4: return reg_[kCtl4];
        default:
            /* Video Control 2,3,5-14 are write-only (§17.4.2-§17.4.14). */
            HaltUnsupportedAccess("PR31x00 LCD ReadWord", addr, 0);
    }
}

void Pr31x00Lcd::WriteWord(uint32_t addr, uint32_t value) {
    switch ((addr - kBase) / 4u) {
        case kCtl1: {
            if (value & kDispSplit) {
                HaltUnsupportedAccess("PR31x00 LCD DISPSPLIT", addr, value);
            }
            if (((value >> kBitSelShift) & 3u) == kBitSel8BitColor) {
                HaltUnsupportedAccess("PR31x00 LCD BITSEL 8-bit color", addr, value);
            }
            const bool was_enabled = (reg_[kCtl1] & kEnVid) != 0u;
            reg_[kCtl1] = value & kCtl1Writable;
            PublishFrameTiming();
            /* Fire only on the ENVID 0->1 edge: the OAL programs VIDEO_CTL2's
               HORZVAL/LINEVAL before it sets ENVID (nk.exe sub_9F434078), so an
               earlier or per-write call would size the window from a stale CTL2. */
            if (!was_enabled && (reg_[kCtl1] & kEnVid)) {
                emu_.Get<HostWindow>().OnLcdEnabled();
            }
            return;
        }

        case kCtl2:
            if (value & kCtl2Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL2 reserved", addr, value);
            }
            reg_[kCtl2] = value;
            PublishFrameTiming();
            return;

        case kCtl3:
            if (value & kCtl3Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL3 reserved", addr, value);
            }
            reg_[kCtl3] = value;
            return;

        case kCtl4:
            if (value & kCtl4Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL4 reserved", addr, value);
            }
            if (value & kCtl4FrameMaskVal) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL4 FRAMEMASKVAL", addr, value);
            }
            reg_[kCtl4] = value;
            return;

        case kCtl5: reg_[kCtl5] = value; return;
        case kCtl6: reg_[kCtl6] = value; return;

        case kCtl7:
            if (value & kCtl7Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL7 reserved", addr, value);
            }
            reg_[kCtl7] = value;
            return;

        case kCtl8:
            if (value & kCtl8Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL8 reserved", addr, value);
            }
            StorePattern(kCtl8, addr, value, kPat2_3Recommended, "PR31x00 LCD PAT2_3 dither pattern");
            return;

        case kCtl9:
            StorePattern(kCtl9, addr, value, kPat3_4Pat2_4Recommended, "PR31x00 LCD PAT3_4/PAT2_4 dither pattern");
            return;

        case kCtl10:
            if (value & kPat20Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL10 reserved", addr, value);
            }
            StorePattern(kCtl10, addr, value, kPat4_5Recommended, "PR31x00 LCD PAT4_5 dither pattern");
            return;

        case kCtl11:
            if (value & kPat20Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL11 reserved", addr, value);
            }
            StorePattern(kCtl11, addr, value, kPat3_5Recommended, "PR31x00 LCD PAT3_5 dither pattern");
            return;

        case kCtl12:
            if (value & kPat28Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL12 reserved", addr, value);
            }
            StorePattern(kCtl12, addr, value, kPat6_7Recommended, "PR31x00 LCD PAT6_7 dither pattern");
            return;

        case kCtl13:
            if (value & kPat28Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL13 reserved", addr, value);
            }
            StorePattern(kCtl13, addr, value, kPat5_7Recommended, "PR31x00 LCD PAT5_7 dither pattern");
            return;

        case kCtl14:
            if (value & kPat28Reserved) {
                HaltUnsupportedAccess("PR31x00 LCD VIDEO_CTL14 reserved", addr, value);
            }
            StorePattern(kCtl14, addr, value, kPat4_7Recommended, "PR31x00 LCD PAT4_7 dither pattern");
            return;

        default:
            HaltUnsupportedAccess("PR31x00 LCD WriteWord", addr, value);
    }
}

void Pr31x00Lcd::StorePattern(uint32_t idx, uint32_t addr, uint32_t value,
                              uint32_t recommended, const char* op) {
    if (value != recommended) {
        HaltUnsupportedAccess(op, addr, value);
    }
    reg_[idx] = value;
}

void Pr31x00Lcd::SaveState(StateWriter& w) {
    for (uint32_t i = 0; i < kRegs; ++i) w.Write("reg", reg_[i]);
}

void Pr31x00Lcd::RestoreState(StateReader& r) {
    for (uint32_t i = 0; i < kRegs; ++i) r.Read("reg", reg_[i]);
}

REGISTER_SERVICE(Pr31x00Lcd);
