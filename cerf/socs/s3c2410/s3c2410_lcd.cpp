#include "s3c2410_lcd.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"

bool S3C2410Lcd::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::S3C2410;
}

void S3C2410Lcd::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t* S3C2410Lcd::DecodeSlot(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off < kCtrlEnd)                   return &ctrl_[(off - kCtrlOff) / 4u];
    if (off >= kPalOff && off < kPalEnd)  return &pal_[(off - kPalOff) / 4u];
    return nullptr;
}

uint32_t S3C2410Lcd::ReadWord(uint32_t addr) {
    uint32_t* slot = DecodeSlot(addr);
    if (!slot) HaltUnsupportedAccess("ReadWord", addr, 0);
    return *slot;
}

void S3C2410Lcd::WriteWord(uint32_t addr, uint32_t value) {
    uint32_t* slot = DecodeSlot(addr);
    if (!slot) HaltUnsupportedAccess("WriteWord", addr, value);
    const uint32_t old = *slot;
    *slot = value;
    /* Fire on ENVID 0→1 edge only — firing on every LCDCON write
       would race with the BSP's size-then-enable sequence and
       publish stale size from a partially-programmed LCDCON2/3. */
    if (slot == &ctrl_[kIdxLCDCON1]
        && ((old & 0x1u) == 0u)
        && ((value & 0x1u) != 0u)) {
        emu_.Get<HostWindow>().OnLcdEnabled(GetGuestW(), GetGuestH());
    }
}

bool S3C2410Lcd::IsEnabled() {
    const uint32_t lcdcon1 = ctrl_[kIdxLCDCON1];
    const uint32_t lcdcon5 = ctrl_[kIdxLCDCON5];

    const uint32_t envid   =  lcdcon1        & 1u;
    if (envid == 0u) return false;

    const uint32_t bppmode = (lcdcon1 >> 1)  & 0xFu;
    const uint32_t pnrmode = (lcdcon1 >> 5)  & 0x3u;
    const bool     frm565  = ((lcdcon5 >> 11) & 1u) != 0u;

    if (pnrmode != kPnrmodeTft || bppmode != kBppmode16bppTft || !frm565) {
        LOG(Caution, "S3C2410Lcd: unsupported mode programmed with "
                "ENVID=1: PNRMODE=%u BPPMODE=%u FRM565=%d. CERF models "
                "16bpp 5:6:5 TFT only (PNRMODE=3 BPPMODE=12 FRM565=1). "
                "Verify ScreenBitsPerPixel=16 in BSP_ARGS so the OAL "
                "drives the kernel into the supported path.\n",
                pnrmode, bppmode, (int)frm565);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return true;
}

uint32_t S3C2410Lcd::GetFbPa() {
    /* LCDSADDR1: bits[29:0] hold phys A[30:1]; shift left 1 to
       recover the byte-aligned framebuffer PA. */
    return (ctrl_[kIdxLCDSADDR1] & 0x3FFFFFFFu) << 1;
}

uint32_t S3C2410Lcd::GetGuestW() {
    /* LCDCON3[18:8] = HOZVAL = width - 1. */
    return ((ctrl_[kIdxLCDCON3] >> 8) & 0x7FFu) + 1u;
}

uint32_t S3C2410Lcd::GetGuestH() {
    /* LCDCON2[23:14] = LINEVAL = height - 1. */
    return ((ctrl_[kIdxLCDCON2] >> 14) & 0x3FFu) + 1u;
}

REGISTER_SERVICE(S3C2410Lcd);
