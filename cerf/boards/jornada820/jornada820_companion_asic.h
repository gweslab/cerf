#pragma once

#include "../../core/byte_order.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/ps2_mouse/ps2_mouse.h"

#include <cstdint>
#include <vector>

/* HP Jornada 820 companion ASIC, nCS3 PA 0x18000000 (uncached VA 0xA4000000).
   Control regs storage-backed; the GlidePad PS/2 controller is at offset
   0x1A0000 - 8042 status +0x400, command/data +0x800 (glidepad.dll). */
class Jornada820CompanionAsic : public Peripheral {
public:
    explicit Jornada820CompanionAsic(CerfEmulator& emu)
        : Peripheral(emu), mouse_([this] { RaiseIrq(); }) {}

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x18000000u; }
    uint32_t MmioSize() const override { return 0x00400000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  v) override;
    void     WriteHalf(uint32_t addr, uint16_t v) override;
    void     WriteWord(uint32_t addr, uint32_t v) override;

    void     SaveState(StateWriter& w) override;
    void     RestoreState(StateReader& r) override;

    void QueuePs2Motion(int dx, int dy, uint32_t button_mask) {
        mouse_.QueueMotion(dx, dy, button_mask);
    }

    /* Raise a PCMCIA card IREQ (socket 0 / 1). Called by Jornada820Pcmcia from
       the card's signalling thread. */
    void RaisePcmciaCardIrq(int socket);

    /* Raise a PCMCIA card-detect / status-change (socket 0 / 1) so the PDD
       detect poller re-scans on a runtime insert/eject. */
    void RaisePcmciaStatusChange(int socket);

private:
    static constexpr uint32_t kPs2Status = 0x1A0400u;
    static constexpr uint32_t kPs2Data   = 0x1A0800u;

    /* PCMCIA socket status reg the CE PDD maps here (pcmcia.dll sub_12A1208:
       off_12A9458 base 0x1E0000, status at +0x800). */
    static constexpr uint32_t kPcmciaStatus = 0x1E0800u;

    /* Companion interrupt controller per nk.exe OEMInterruptHandler sub_80059BB0
       (reads/W1C-acks +0x166400) and OEMInterruptEnable sub_8005A858 (sets the
       enable mask +0x162400). A source asserts -> set its pending bit (iff
       masked) + pulse the aggregate output GPIO14. */
    static constexpr uint32_t kIntrStatus = 0x166400u;  /* W1C pending */
    static constexpr uint32_t kIntrMask   = 0x162400u;  /* enable mask  */
    static constexpr uint32_t kSrcMouse   = 0x800u;       /* bit11 -> SYSINTR 29 */
    static constexpr uint32_t kSrcCard0   = 0x2000000u;   /* bit25 -> SYSINTR 28 */
    static constexpr uint32_t kSrcCard1   = 0x4000000u;   /* bit26 -> SYSINTR 28 */
    static constexpr uint32_t kSrcStat0   = 0x8000000u;   /* bit27 -> SYSINTR 27 */
    static constexpr uint32_t kSrcStat1   = 0x10000000u;  /* bit28 -> SYSINTR 27 */

    void RaiseIrq();   /* mouse 8042 IRQ (bit11) */
    void RaiseIntrSource(uint32_t bit);
    void PulseGpio14();
    uint32_t IntrMask() const { return cerf::le::U32(store_.data(), kIntrMask); }
    uint8_t Ps2StatusByte() { return 0x80u | (mouse_.HasData() ? 0x20u : 0u); }

    std::vector<uint8_t> store_;
    uint32_t             intr_pending_ = 0;
    Ps2Mouse             mouse_;
};
