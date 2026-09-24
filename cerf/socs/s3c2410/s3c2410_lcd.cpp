#include "s3c2410_lcd.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool S3C2410Lcd::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::S3c2410;
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
    /* Fire on ENVID 0→1 edge only - firing on every LCDCON write
       would race with the BSP's size-then-enable sequence and
       publish stale size from a partially-programmed LCDCON2/3. */
    if (slot == &ctrl_[kIdxLCDCON1]
        && ((old & 0x1u) == 0u)
        && ((value & 0x1u) != 0u)) {
        emu_.Get<HostWindow>().OnLcdEnabled();
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

    /* 16bpp 5:6:5-direct and 8bpp-palettized both read framebuffer or
       palette entries as 5:6:5, so both require FRM565=1; the 8bpp
       5:5:5:1 palette format is not modeled. */
    const bool ok16 = pnrmode == kPnrmodeTft && bppmode == kBppmode16bppTft && frm565;
    const bool ok8  = pnrmode == kPnrmodeTft && bppmode == kBppmode8bppTft  && frm565;
    if (!ok16 && !ok8) {
        LOG(Caution, "S3C2410Lcd: unsupported mode programmed with "
                "ENVID=1: PNRMODE=%u BPPMODE=%u FRM565=%d. CERF models "
                "16bpp 5:6:5 (BPPMODE=12) and 8bpp palettized (BPPMODE=11) "
                "TFT only, both with PNRMODE=3 FRM565=1.\n",
                pnrmode, bppmode, (int)frm565);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return true;
}

bool S3C2410Lcd::IsPalettized() {
    return ((ctrl_[kIdxLCDCON1] >> 1) & 0xFu) == kBppmode8bppTft;
}

uint32_t S3C2410Lcd::GetBytesPerPixel() {
    return IsPalettized() ? 1u : 2u;
}

uint16_t S3C2410Lcd::GetPaletteEntry565(uint8_t index) {
    /* TFT palette slot: 256 32-bit words at 0x400, low 16 bits = the
       5:6:5 color (S3C2410A UM §15, 256 PALETTE USAGE). */
    return (uint16_t)(pal_[index] & 0xFFFFu);
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

void S3C2410Lcd::SaveState(StateWriter& w) {
    w.WriteBytes("ctrl", ctrl_, sizeof(ctrl_));
    w.WriteBytes("pal", pal_,  sizeof(pal_));
}

void S3C2410Lcd::RestoreState(StateReader& r) {
    r.ReadBytes("ctrl", ctrl_, sizeof(ctrl_));
    r.ReadBytes("pal", pal_,  sizeof(pal_));
}

REGISTER_SERVICE(S3C2410Lcd);
