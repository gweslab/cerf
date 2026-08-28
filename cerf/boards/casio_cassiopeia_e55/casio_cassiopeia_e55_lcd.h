#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../lcd/display_size_latch.h"

#include <cstdint>
#include <vector>

/* casio_cassiopeia_e55 ddi.dll sub_14F0C28 @0x14F0D34-@0x14F0D48 maps this window:
   li $a2, 0x1FFFF / lw $a1, dword_14F845C / jal VirtualCopy / li $a3, 0x204, with
   $a0 = dword_14FA534. dword_14F845C = 0xAA000000, KSEG1 of PA 0x0A000000. VR4111 UM
   11.5.3 p296 decodes 0x0A000000-0x0AFFFFFF to an external LCD controller. */
class CasioCassiopeiaE55Lcd : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kWindowSize; }

    uint8_t  ReadByte(uint32_t addr) override;
    uint16_t ReadHalf(uint32_t addr) override;
    uint32_t ReadWord(uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    bool           IsDisplayEnabled();
    void           MaybePublishDisplaySize();

    /* casio_cassiopeia_e55 ddi.dll sub_14F16D0 @0x14F170C sw 8($s0) = dword_14F8460 240,
       @0x14F173C sw 0xC($s0) = dword_14F8464 320, @0x14F1728 sw 0x24($s0) = 2 bpp;
       @0x14F17F4/@0x14F1814/@0x14F1818 pass 4 * dword_14F8478 as sub_14F34F0's a5, whose
       body is a1[2] = a5, so the stride is 4 * 64 = 256. */
    static constexpr uint32_t kVisibleW   = 240u;
    static constexpr uint32_t kVisibleH   = 320u;
    static constexpr uint32_t kPitchBytes = 256u;
    static constexpr uint32_t kBpp        = 2u;

    uint32_t       GuestW()      const { return kVisibleW; }
    uint32_t       GuestH()      const { return kVisibleH; }
    uint32_t       StrideBytes() const { return kPitchBytes; }
    uint32_t       FbPa()        const { return kBase + kFbOffset; }
    uint32_t       FbSize()      const { return kFbSize; }
    const uint8_t* FbBytes()     const { return fb_.data(); }

private:
    static constexpr uint32_t kBase       = 0x0A000000u;
    static constexpr uint32_t kWindowSize = 0x00020000u;
    static constexpr uint32_t kFbOffset   = 0x00000000u;
    static constexpr uint32_t kFbSize     = kPitchBytes * kVisibleH;

    /* casio_cassiopeia_e55 nk.exe sub_9E814C70 @0x9E814C70-@0x9E814CE8 and ddi.dll
       sub_14F0DE0 @0x14F0E74-@0x14F0F04 store 0xF4 0xC4 0xB0 0xD0 twice to these offsets;
       nk.exe @0x9E816B70-@0x9E816BA4 stores 0xF4 0x84 0xB0 0xD0 twice. The sequences differ
       only at indices 1 and 5. */
    static constexpr uint32_t kCtrlOffset = 0x0001FFF0u;
    static constexpr uint32_t kCtrlCount  = 8u;

    /* casio_cassiopeia_e55 ddi.dll sub_14F0DE0 @0x14F0F30-@0x14F0F3C and nk.exe
       @0x9E816BB0-@0x9E816BC0 set bit 0x200 of PA 0x0B000106 (GIUPIODH, GPIO(31:16)), cleared
       by sub_14F0DE0's a1 == 1 arm; nk.exe @0x9E814504-@0x9E814508 sets GIUIOSELH
       (PA 0x0B000102) = 0x1FC0, whose bit 9 makes GPIO25 an output that reads back. */
    static constexpr int kPanelEnableGpio = 25;

    bool InFb(uint32_t off)   const { return off < kFbOffset + kFbSize; }
    bool InCtrl(uint32_t off) const {
        return off >= kCtrlOffset && off < kCtrlOffset + kCtrlCount;
    }

    std::vector<uint8_t> fb_;
    uint8_t              ctrl_[kCtrlCount] = {};
    DisplaySizeLatch     size_latch_;
};
