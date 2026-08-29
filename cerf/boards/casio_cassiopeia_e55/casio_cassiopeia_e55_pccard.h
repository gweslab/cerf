#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../peripherals/pcmcia/pcmcia_slot.h"

#include <cstdint>

class StateReader;
class StateWriter;

/* casio_cassiopeia_e55 pcmcia.dll sub_14C1604 @0x14C1604 reports the card aperture as
   0xB400E000-0xB400E7FF when dword_14C95D4 is 1, which sub_14C0728 @0x14C0728 sets from
   companion-ASIC +0x14 D1; the other strap reports 0xB400C000-0xB400C7FF. Both spans are
   0x800 bytes. */
class CasioCassiopeiaE55PcCard : public Peripheral, public PcmciaSlotHost {
public:
    explicit CasioCassiopeiaE55PcCard(CerfEmulator& emu);

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;

    uint8_t  ReadByte (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t value) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    void SetRegSpace(bool on);
    void SetSocketPower(bool on);
    void SetResetStrobe(bool on);

    uint8_t  ReadIo8  (uint32_t off);
    uint16_t ReadIo16 (uint32_t off);
    void     WriteIo8 (uint32_t off, uint8_t  value);
    void     WriteIo16(uint32_t off, uint16_t value);

    /* casio_cassiopeia_e55 pcmcia.dll sub_14C0B84 @0x14C0B84 reports a card when
       (+0x04 & 6) == 0 and reports not-ready when (+0x04 & 1) == 0; sub_14C0E8C @0x14C0E8C
       takes the no-card arm on (+0x04 & 6) != 0 and, after releasing the reset strobe,
       polls (+0x04 & 1) for up to 2050 ms and fails the socket if it never sets. */
    uint16_t StatusReg() const;

    void OnCardDetectChanged(PcmciaSlot& slot) override;
    void OnCardIrqAsserted  (PcmciaSlot& slot) override;
    void OnCardIrqDeasserted(PcmciaSlot& slot) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    PcmciaSlot slot0_;
    bool       reg_space_ = false;
    bool       in_reset_  = false;
};
