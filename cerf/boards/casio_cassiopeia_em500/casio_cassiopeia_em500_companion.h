#pragma once

#include "../../peripherals/peripheral_base.h"

#include "casio_cassiopeia_em500_audio.h"
#include "casio_cassiopeia_em500_display.h"
#include "casio_cassiopeia_em500_eeprom.h"
#include "casio_cassiopeia_em500_modem.h"
#include "casio_cassiopeia_em500_touch.h"

#include <atomic>
#include <cstdint>

/* Casio companion ASIC in External I/O area 2 (IOCS0#), PA 0x0A000000 (kseg1
   0xAA000000; VR4131 UM U15350EJ2V0UM Fig 3-1 p75); registers from
   nk_main_kernel.exe sub_9F032B60, sub_9F0389EC, sub_9F03445C, sub_9F0346B0,
   and ddi.dll sub_FC5538/sub_FC4E38. */
class CasioCassiopeiaEm500Companion : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kWindowSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    void SetTouchPen(bool down, int x, int y) { touch_.SetPen(down, x, y); }
    void TouchCaptureLost() { touch_.OnCaptureLost(); }

    bool IsDisplayEnabled() const { return display_.IsDisplayEnabled(); }
    uint32_t GuestW()      const { return display_.GuestW(); }
    uint32_t GuestH()      const { return display_.GuestH(); }
    uint32_t StrideBytes() const { return display_.StrideBytes(); }
    uint32_t FbPa()        const { return display_.FbPa(); }
    const uint8_t* FbBytes() const { return display_.FbBytes(); }

private:
    static constexpr uint32_t kBase       = 0x0A000000u;
    static constexpr uint32_t kWindowSize = 0x00240000u;

    void WriteReg(uint32_t off, uint32_t value);
    void WriteCodecCommand(uint32_t value);
    void WriteSysCtrl(uint32_t off, uint32_t value, uint32_t keep_mask);
    void UpdateAudioIrqLine();

    CasioCassiopeiaEm500Audio audio_;
    CasioCassiopeiaEm500Display display_;
    CasioCassiopeiaEm500Eeprom eeprom_;
    CasioCassiopeiaEm500Modem modem_;
    CasioCassiopeiaEm500Touch touch_;

    /* nk_main_kernel.exe sub_9F03C104 @0x9F03C120, sub_9F03C140 @0x9F03C160,
       @0x9F033174/@0x9F0331B8. */
    uint32_t mbox_cmd_ = 0;
    /* nk_main_kernel.exe sub_9F0389EC @0x9F0389EC */
    uint32_t ctrl8904_ = 0;
    /* nk_main_kernel.exe @0x9F0331FC-0x9F033284 (bit0/bit1 RMW pulses). */
    uint32_t ctrl_a0d4_ = 0;
    /* nk_main_kernel.exe @0x9F03C188-0x9F03C194; sub_9F08EE0C SYSINTR-19/28/30/31. */
    uint32_t clk8004_ = 0;
    /* nk_main_kernel.exe sub_9F038A58 @0x9F038A60 */
    uint16_t data_a040_ = 0;
    /* nk_main_kernel.exe @0x9F032CDC, sub_9F03473C @0x9F034834/@0x9F034844. */
    uint32_t reg_1110_ = 0;
    /* nk_main_kernel.exe writes @0x9F08EF7C/@0x9F03C330/@0x9F03C338; store-only,
       read side sub_9F03C304 @0x9F03C308 born-FATAL until hit. */
    uint32_t reg_1054_ = 0;
    /* pcmcia.dll @0xF81878/@0xF81880 (RMW |0x30). */
    uint32_t socket_ctrl_ac8_ = 0;
    /* pcmcia.dll @0xF81D76/@0xF81D80 (RMW &~0xC). */
    uint32_t socket_a038_ = 0;
    /* nk_main_kernel.exe sub_9F08EE0C @0x9F08EE28/@0x9F08EE34. */
    uint16_t intcfg8404_ = 0;
    /* wavedev.dll 0x03C0 register file; 0x03F4 data port latched by the 0x5000
       read command @0xF629F6 and read at @0xF62A04. */
    uint16_t codec_regs_[6] = {};
    uint8_t  codec_written_ = 0;
    uint32_t codec_data_ = 0;
    bool     codec_data_valid_ = false;
    uint32_t latch1118_ = 0;
    /* nk_main_kernel.exe @0x9F035930 (sw 0x10), idle @0x9F0388F4 (lw; andi 1). */
    uint32_t latch130C_ = 0;
    /* socket.dll @0xF41978-0xF41984 (0x4000 -> table[4]=+0 @0xF421D2, desc
       0xAA008000 @0xF421F8) via sub_F42258 store. */
    uint32_t strap8000_ = 0;
    /* remocon.dll mapper @0xED181C-0xED1820 (base+0x89C); init RMW @0xED158C
       (&~0x38); IST @0xED15D6-0xED15E4 (&~0x30|8), @0xED1682-0xED168C (&~0x38);
       gate sub_ED19A0 (&0x40). */
    uint32_t adc_ctrl_89C_ = 0;
    /* nk_main_kernel.exe sub_9F08F334 case17 @0x9F08F388 / case24 @0x9F08F3A4
       (RMW enable config), @0x9F033A84 (sw 0); consumed @0x9F036608 (lw 0x304;
       raw & (raw>>8) = pending[7:0] & enable[15:8] cascade demux). */
    uint32_t reg_0304_ = 0;
    /* nk_main_kernel.exe @0x9F033118/@0x9F033130 (0x0910), @0x9F0331D8-0x9F0331F0
       (0x0900/0x0908/0x090C). */
    uint32_t sib_regs_[5] = {};
    /* nk_main_kernel.exe sub_9F038AF0 @0x9F038AF8 */
    std::atomic<uint32_t> sys_ctrl_[16] = {};
    /* nk_main_kernel.exe @0x9F0330DC-0x9F0330F0; keybddr.dll sub_FB1F80
       base+(0x30+i)*2, i=0..15. */
    uint16_t edge_cfg_[16] = {};

};
