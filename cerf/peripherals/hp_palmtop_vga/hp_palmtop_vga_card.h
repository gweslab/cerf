#pragma once

#include "../pcmcia/pcmcia_card.h"
#include "../../host/external_display_window.h"
#include "vga_controller.h"

#include <cstdint>
#include <memory>

/* HP F1252A "HP Palmtop VGA" PC Card - a standard VGA-compatible SVGA
   controller on a 16-bit PC Card that drives an external monitor. Board-
   agnostic: pluggable into any slot via the catalog. On the Jornada 720 the
   stock ROM auto-detects it (registry Detect\49 -> hpvgaout!DetectVGA, which
   reads the HP identity magic at attribute-memory 0xC0000), loads
   hpvgaout/pcvgaout, and renders an 8/16bpp framebuffer.

   PC-Card space layout (reverse-engineered hpvgaout sub_100045DC /
   sub_1000451C, then confirmed by runtime trace of the ROM driver's actual
   accesses):
     - ATTRIBUTE memory: the CIS at low offsets + the HP identity magic at
       0xC0000 (DetectVGA's CardRequestWindow/CardMapWindow targets attribute).
     - I/O space: the VGA register file (the driver's register writes -
       0x3C0..0x46E8, 0x43Cx - decode into the PCMCIA I/O region).
     - COMMON memory: the linear framebuffer at 0x200000.
   Registers + framebuffer route to the VgaController; the card presents the
   controller in its own ExternalDisplayWindow. */
class HpPalmtopVgaCard : public PcmciaCard {
public:
    static constexpr const wchar_t* kDisplayName = L"HP Palmtop VGA (F1252A)";

    explicit HpPalmtopVgaCard(CerfEmulator& emu);
    ~HpPalmtopVgaCard() override;

    std::wstring DisplayName() const override { return kDisplayName; }
    std::wstring MenuLabel() const override;
    std::wstring TooltipDetail() const override { return MenuLabel(); }
    const wchar_t* IconResource() const override { return L"ICON_PCMCIA_VGA"; }

    void OnInserted() override;
    void OnShutdown() override;

    void PowerOn () override;

    const char* SaveId() const override { return "hpvga"; }
    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PowerOff() override;

    uint8_t  ReadAttribute8 (uint32_t offset)                override;
    void     WriteAttribute8(uint32_t offset, uint8_t value) override;

    uint8_t  ReadCommon8  (uint32_t offset)                  override;
    uint16_t ReadCommon16 (uint32_t offset)                  override;
    void     WriteCommon8 (uint32_t offset, uint8_t  value)  override;
    void     WriteCommon16(uint32_t offset, uint16_t value)  override;

    uint8_t  ReadIo8  (uint32_t offset)                      override;
    uint16_t ReadIo16 (uint32_t offset)                      override;
    void     WriteIo8 (uint32_t offset, uint8_t  value)      override;
    void     WriteIo16(uint32_t offset, uint16_t value)      override;

private:
    /* Re-poll the controller's mode after a register write; size/show the
       window when the geometry changes. */
    void SyncWindowToMode();

    /* Card-space offsets (region per the layout note above: registers I/O,
       magic attribute, framebuffer common). */
    static constexpr uint32_t kRegBase   = 0x000000u;
    static constexpr uint32_t kRegEnd    = 0x0046E9u;   /* sub_100045DC size */
    static constexpr uint32_t kMagicBase = 0x0C0000u;
    static constexpr uint32_t kMagicLen  = 8u;
    static constexpr uint32_t kFbBase    = 0x200000u;

    VgaController controller_;
    std::unique_ptr<ExternalDisplayWindow> window_;

    uint32_t last_w_ = 0, last_h_ = 0;
};
