#define NOMINMAX

#include "devemu_touch_panel.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_canvas.h"
#include "../../host/touch_input.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/irq_controller.h"
#include "../board_detector.h"

REGISTER_SERVICE(DevEmuTouchPanel);

namespace {

/* Register offsets relative to base 0x58000000. Five 32-bit registers,
   4-byte stride. */
constexpr uint32_t kRegADCCON  = 0x00u;
constexpr uint32_t kRegADCTSC  = 0x04u;
constexpr uint32_t kRegADCDLY  = 0x08u;
constexpr uint32_t kRegADCDAT0 = 0x0Cu;
constexpr uint32_t kRegADCDAT1 = 0x10u;

/* Register field layouts pulled from the BSP IOADConverter's bitfield
   unions in dev_emu boards/smdk2410/devices.h (ADCCON, ADCTSC,
   ADCDAT0, ADCDAT1 anonymous structs there). */
constexpr uint32_t kAdcconEnableStart = 0x0001u;  /* ADCCON.ENABLE_START — bit 0 */
constexpr uint32_t kAdcconEcflg       = 0x8000u;  /* ADCCON.ECFLG       — bit 15 */
constexpr uint32_t kAdctscXyPstMask   = 0x0003u;  /* ADCTSC.XY_PST      — bits 0..1 */
constexpr uint32_t kAdcdatXpdataMask  = 0x03FFu;  /* ADCDAT0.XPDATA / ADCDAT1.YPDATA — bits 0..9 (10-bit sample) */
constexpr uint32_t kAdcdatXyPstShift  = 12u;      /* ADCDAT0.XY_PST     — bits 12..13 */
constexpr uint32_t kAdcdatXyPstMask   = 0x3000u;
constexpr uint32_t kAdcdatUpdown      = 0x8000u;  /* ADCDAT0.UPDOWN / ADCDAT1.UPDOWN — bit 15 (1 = pen up) */

constexpr int kIrqAdc   = 31;
constexpr int kIrqSubTc =  9;

/* IOADConverter::SetPenSample: X = 90 + host_x*(875/screen_x);
   Y = 920 - host_y*(870/screen_y), Y inverted (chip 0 = bottom). */
constexpr int    kSampleXOffset = 90;
constexpr double kSampleXSpan   = 875.0;
constexpr int    kSampleYOrigin = 920;
constexpr double kSampleYSpan   = 870.0;

/* TouchInput adapter — anonymous-namespaced, forwards host pointer
   events to the DevEmuTouchPanel concrete; nothing outside this .cpp
   needs to name the adapter type. */
class DevEmuTouchInput : public TouchInput {
public:
    using TouchInput::TouchInput;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }
    void OnPenDown(int x, int y) override {
        emu_.Get<DevEmuTouchPanel>().OnPenDown(x, y);
    }
    void OnPenMove(int x, int y) override {
        emu_.Get<DevEmuTouchPanel>().OnPenMove(x, y);
    }
    void OnPenUp(int x, int y) override {
        emu_.Get<DevEmuTouchPanel>().OnPenUp(x, y);
    }
    void OnCaptureLost() override {
        emu_.Get<DevEmuTouchPanel>().OnCaptureLost();
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(DevEmuTouchInput, TouchInput);

bool DevEmuTouchPanel::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
}

void DevEmuTouchPanel::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);

    /* Without UPDOWN set here, the kernel's first sample reads
       pen-down and registers a phantom tap; the BSP relies on a
       SetPenState from the first capture event we can't reproduce. */
    std::lock_guard<std::mutex> lk(state_mutex_);
    adcdat0_ |= kAdcdatUpdown;
    adcdat1_ |= kAdcdatUpdown;
}

uint32_t DevEmuTouchPanel::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case kRegADCCON:  value = adccon_;  break;
            case kRegADCTSC:  value = adctsc_;  break;
            case kRegADCDLY:  value = adcdly_;  break;
            case kRegADCDAT0: value = adcdat0_; break;
            case kRegADCDAT1: value = adcdat1_; break;
            default:
                HaltUnsupportedAccess("ReadWord", addr, 0);  /* noreturn */
        }
    }
    LOG(Periph, "[Touch] read  +0x%02X -> 0x%08X\n", off, value);
    return value;
}

void DevEmuTouchPanel::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    LOG(Periph, "[Touch] write +0x%02X = 0x%08X\n", off, value);
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
        case kRegADCCON:
            adccon_ = value;
            if (adccon_ & kAdcconEnableStart) {
                /* BSP axis swap: ADCDAT0/XPDATA holds the Y sample,
                   ADCDAT1/YPDATA holds X (BSP: "XPDATA really does
                   contain the Y sample"). */
                adccon_ &= ~kAdcconEnableStart;
                adccon_ |=  kAdcconEcflg;
                adcdat0_ = (adcdat0_ & ~kAdcdatXpdataMask) |
                           (sample_y_ & kAdcdatXpdataMask);
                adcdat1_ = (adcdat1_ & ~kAdcdatXpdataMask) |
                           (sample_x_ & kAdcdatXpdataMask);
            }
            break;
        case kRegADCTSC:
            adctsc_ = value;
            break;
        case kRegADCDLY:
            adcdly_ = value;
            break;
        case kRegADCDAT0:
        case kRegADCDAT1:
            /* Read-only on the real chip — IOADConverter::WriteWord
               explicitly drops these. */
            break;
        default:
            HaltUnsupportedAccess("WriteWord", addr, value);  /* noreturn */
    }
}

void DevEmuTouchPanel::SetPenStateLocked(bool pen_up) {
    /* Mirrors IOADConverter::SetPenState: snapshot the current ADCTSC
       XY_PST into ADCDAT0's XY_PST field, set/clear UPDOWN in both
       data registers. ADCDAT1's XY_PST isn't touched — the BSP
       implementation only copies into ADCDAT0. */
    const uint32_t xy_pst_shifted =
        (adctsc_ & kAdctscXyPstMask) << kAdcdatXyPstShift;

    const uint32_t updown_bit = pen_up ? kAdcdatUpdown : 0u;

    adcdat0_ = (adcdat0_ & ~(kAdcdatXyPstMask | kAdcdatUpdown))
             | xy_pst_shifted
             | updown_bit;
    adcdat1_ = (adcdat1_ & ~kAdcdatUpdown)
             | updown_bit;
}

void DevEmuTouchPanel::UpdateSampleLocked(int host_x, int host_y) {
    /* IOADConverter::SetPenSample guard: XY_PST!=0 AND UPDOWN==0. */
    if ((adcdat0_ & kAdcdatXyPstMask) == 0) return;
    if  (adcdat0_ & kAdcdatUpdown)          return;

    auto&        hc       = emu_.Get<HostCanvas>();
    const double screen_x = (double)hc.GuestSurfaceWidth ();
    const double screen_y = (double)hc.GuestSurfaceHeight();

    sample_x_ = (uint16_t)(kSampleXOffset +
                           (int)((double)host_x * (kSampleXSpan / screen_x)));
    sample_y_ = (uint16_t)(kSampleYOrigin -
                           (int)((double)host_y * (kSampleYSpan / screen_y)));
}

void DevEmuTouchPanel::RaiseTCInterrupt() {
    emu_.Get<IrqController>().AssertSubIrq(kIrqAdc, kIrqSubTc);
}

void DevEmuTouchPanel::OnPenDown(int host_x, int host_y) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        /* Order matches IOLCDController::onWM_LBUTTONDOWN: state first
           (so UpdateSampleLocked's UPDOWN==0 guard passes), then
           sample. */
        SetPenStateLocked(/*pen_up=*/false);
        UpdateSampleLocked(host_x, host_y);
    }
    RaiseTCInterrupt();
}

void DevEmuTouchPanel::OnPenMove(int host_x, int host_y) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    UpdateSampleLocked(host_x, host_y);
}

void DevEmuTouchPanel::OnPenUp(int host_x, int host_y) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        /* Order matches IOLCDController::onWM_LBUTTONUP: sample first
           (while UPDOWN is still 0 from the prior pen-down so the
           UPDOWN==0 guard inside SetPenSample admits the write), then
           state transition. */
        UpdateSampleLocked(host_x, host_y);
        SetPenStateLocked(/*pen_up=*/true);
    }
    RaiseTCInterrupt();
}

void DevEmuTouchPanel::OnCaptureLost() {
    /* Capture lost without a pen-up: re-raise TC so the ISR
       latches the final state. */
    bool needs_raise = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (adcdat0_ & kAdcdatUpdown) {
            SetPenStateLocked(/*pen_up=*/true);
            needs_raise = true;
        }
    }
    if (needs_raise) RaiseTCInterrupt();
}
