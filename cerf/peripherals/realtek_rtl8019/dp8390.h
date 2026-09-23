#pragma once

#include "../../net/mac_address.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

class Rtl8019;
class StateWriter;
class StateReader;

namespace dp8390 {

/* DP8390D datasheet, 1992 National LAN databook, CR p. 1-149. */
inline constexpr uint8_t kCrStp = 0x01;
inline constexpr uint8_t kCrSta = 0x02;
inline constexpr uint8_t kCrTxp = 0x04;
inline constexpr uint8_t kCrRd2 = 0x20;

/* DP8390D datasheet, 1992 National LAN databook, ISR p. 1-150. */
inline constexpr uint8_t kIsrPrx = 0x01;
inline constexpr uint8_t kIsrPtx = 0x02;
inline constexpr uint8_t kIsrOvw = 0x10;
inline constexpr uint8_t kIsrCnt = 0x20;
inline constexpr uint8_t kIsrRdc = 0x40;
inline constexpr uint8_t kIsrRst = 0x80;

/* DP8390D datasheet, 1992 National LAN databook, RCR p. 1-155. */
inline constexpr uint8_t kRcrSaveErrored = 0x01;
inline constexpr uint8_t kRcrAcceptRunt  = 0x02;
inline constexpr uint8_t kRcrBroadcast   = 0x04;
inline constexpr uint8_t kRcrMulticast   = 0x08;
inline constexpr uint8_t kRcrPromiscuous = 0x10;
inline constexpr uint8_t kRcrMonitor     = 0x20;

/* DP8390D datasheet, 1992 National LAN databook, TCR p. 1-153. */
inline constexpr uint8_t kTcrLoopbackBits = 0x06;
inline constexpr uint8_t kTcrAtd          = 0x08;
inline constexpr uint8_t kTcrOfst         = 0x10;

/* DP8390D datasheet, 1992 National LAN databook, DCR p. 1-152. */
inline constexpr uint8_t kDcrWts            = 0x01;
inline constexpr uint8_t kDcrBos            = 0x02;
inline constexpr uint8_t kDcrLongAddress    = 0x04;
inline constexpr uint8_t kDcrLoopbackSelect = 0x08;

/* DP8390D datasheet, 1992 National LAN databook, RSR p. 1-156. */
inline constexpr uint8_t kRsrPrx = 0x01;
inline constexpr uint8_t kRsrMpa = 0x10;
inline constexpr uint8_t kRsrPhy = 0x20;
inline constexpr uint8_t kRsrDis = 0x40;

/* DP8390D datasheet, 1992 National LAN databook, tally counters
   p. 1-159: "The maximum count reached by any counter is 192 (C0H)". */
inline constexpr uint8_t kTallyMax = 0xC0;

/* DP8390D datasheet, 1992 National LAN databook, AUTODIN II generator
   p. 1-133. */
inline constexpr uint32_t kAutodinIIPoly = 0x04C11DB7u;

}

class Dp8390 {
public:
    /* linux-2.6.25 drivers/net/pcmcia/pcnet_cs.c:61-62 -
       PCNET_START_PG 0x40, PCNET_STOP_PG 0x80. */
    static constexpr uint32_t kRamBase = 0x4000u;
    static constexpr uint32_t kRamSize = 0x4000u;
    static constexpr std::size_t kRomSize = 32;

    Dp8390(Rtl8019& card,
           std::array<uint8_t, kRomSize>& rom,
           std::array<uint8_t, kRamSize>& ram);

    /* PC Card Standard Vol. 2 Electrical, 4.12.2: on RESET or SRESET
       "a card shall return to the power-up state". */
    void PowerUpLocked();

    /* DP8390D datasheet, 1992 National LAN databook, 11.0 reset table
       p. 1-159. */
    void ResetLocked();

    /* DP8390D datasheet, 1992 National LAN databook, ISR p. 1-150: "The
       INT signal is active as long as any unmasked signal is set", and
       RST "does not generate an interrupt". */
    bool IrqPendingLocked() const;
    void RecomputeIrqLocked();

    uint8_t  IoRead8Locked  (uint32_t offset);
    uint16_t IoRead16Locked (uint32_t offset);
    void     IoWrite8Locked (uint32_t offset, uint8_t value,
                             std::vector<uint8_t>& tx_pending);
    void     IoWrite16Locked(uint32_t offset, uint16_t value);

    void CompleteTxLocked();

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    friend class Dp8390Receiver;

    void RaiseIsrLocked(uint8_t bits);
    void BumpCntr2Locked();

    /* QEMU hw/net/ne2000.c ne2000_dma_update - reimplemented model. */
    void DmaAdvanceLocked(uint16_t step);
    uint8_t DmaMemReadLocked(uint16_t addr) const;
    void    DmaMemWriteLocked(uint16_t addr, uint8_t value);

    void TransmitLocked(std::vector<uint8_t>& out_frame);

    Rtl8019& card_;
    std::array<uint8_t, kRomSize>& rom_;
    std::array<uint8_t, kRamSize>& ram_;

    bool rst_overflow_ = false;

    /* DP8390D datasheet, 1992 National LAN databook, register address
       assignments p. 1-147; CR bit map p. 1-149. */
    uint8_t cr_ = 0u;

    uint8_t  pstart_ = 0u;
    uint8_t  pstop_  = 0u;
    uint8_t  bnry_   = 0u;
    uint8_t  tsr_    = 0u;
    uint8_t  tpsr_   = 0u;
    uint8_t  ncr_    = 0u;
    uint8_t  isr_    = 0u;
    uint8_t  rcr_    = 0u;
    uint8_t  tcr_    = 0u;
    uint8_t  dcr_    = 0u;
    uint8_t  rsr_    = 0u;
    uint8_t  imr_    = 0u;
    uint16_t tbcr_   = 0u;
    uint16_t rsar_   = 0u;
    uint16_t rbcr_   = 0u;
    uint16_t crda_   = 0u;

    /* DP8390D datasheet, 1992 National LAN databook, network tally
       counters p. 1-159. */
    uint8_t cntr0_ = 0u;
    uint8_t cntr1_ = 0u;
    uint8_t cntr2_ = 0u;

    cerf::inet::MacAddress par_{};
    std::array<uint8_t, 8> mar_{};
    uint8_t                curr_ = 0u;

    uint16_t dma_remaining_ = 0u;
};
