#pragma once

#include "../../boards/board_context.h"

#include <cstdint>

namespace cerf_vr41xx_piu_detail {

/* VR4121 UM Table 20-1 == VR4102 UM Table 19-1. */
constexpr uint32_t kOffCnt  = 0x02u;   /* PIUCNTREG  (VR4121 20.3.1, VR4102 19.3.1) */
constexpr uint32_t kOffInt  = 0x04u;   /* PIUINTREG  (VR4121 20.3.2, VR4102 19.3.2) */
constexpr uint32_t kOffSivl = 0x06u;   /* PIUSIVLREG (VR4121 20.3.3, VR4102 19.3.3) */
constexpr uint32_t kOffStbl = 0x08u;   /* PIUSTBLREG (VR4121 20.3.4, VR4102 19.3.4) */
constexpr uint32_t kOffCmd  = 0x0Au;   /* PIUCMDREG  (VR4121 20.3.5, VR4102 19.3.5) */
constexpr uint32_t kOffAscn = 0x10u;   /* PIUASCNREG (VR4121 20.3.6, VR4102 19.3.6) */
constexpr uint32_t kOffAmsk = 0x12u;   /* PIUAMSKREG (VR4121 20.3.7, VR4102 19.3.7) */

/* PIUABnREG at 0x0B0002B0-0x0B0002B6, in the PIU's second window at 0x0B0002A0 (VR4121 UM
   20.3.10, VR4102 UM 19.3.10). */
constexpr uint32_t kOffAb0 = 0x10u;
constexpr uint32_t kOffAb1 = 0x12u;
constexpr uint32_t kOffAb2 = 0x14u;
constexpr uint32_t kOffAb3 = 0x16u;

/* PIUCNTREG D12:10 PADSTATE "scan sequencer status" (VR4121 UM 20.3.1, VR4102 UM 19.3.1). */
enum : uint16_t {
    kStDisable      = 0,
    kStStandby      = 1,
    kStAdPortScan   = 2,
    kStWaitPenTouch = 4,
    kStPenDataScan  = 5,
    kStIntervalNext = 6,
    kStCmdScan      = 7,
};

/* PIUCNTREG D9 PADATSTOP, D8 PADATSTART, D7 PADSCANSTOP, D6 PADSCANSTART, D5 PADSCANTYPE,
   D4:3 PIUMODE, D2 PIUSEQEN, D1 PIUPWR, D0 PADRST (VR4121 UM 20.3.1, VR4102 UM 19.3.1). */
enum : uint16_t {
    kPadRst = 0x0001, kPiuPwr = 0x0002, kSeqEn = 0x0004,
    kScanStart = 0x0040, kScanStop = 0x0080, kAtStart = 0x0100, kAtStop = 0x0200,
    kCntStored  = 0x033Eu,
};

/* PIUASCNREG D1 TPPSCAN "0: ADIN(2:0)/AUDIOIN as A/D port", D0 ADPSSTART "1: Start ADPortScan"
   (VR4121 UM 20.3.6, VR4102 UM 19.3.6). */
enum : uint16_t { kAdpsStart = 0x0001, kTppScan = 0x0002 };

/* PIUINTREG D15 OVP "valid page ID bit (older valid page)"; D6 PADCMDINTR, D5 PADADPINTR,
   D4 PADPAGE1INTR, D3 PADPAGE0INTR, D2 PADDLOSTINTR, D0 PENCHGINTR, each "cleared to 0 when
   1 is written" (VR4121 UM 20.3.2, VR4102 UM 19.3.2). */
enum : uint16_t {
    kPenChgIntr   = 0x0001, kPadDlostIntr = 0x0004, kPage0Intr = 0x0008,
    kPage1Intr    = 0x0010, kPadAdpIntr   = 0x0020, kPadCmdIntr = 0x0040,
    kIntCauses = kPenChgIntr | kPadDlostIntr | kPage0Intr | kPage1Intr |
                 kPadAdpIntr | kPadCmdIntr,
    kOvp = 0x8000u,
};

/* PIUPBnmREG / PIUABnREG D15 VALID + D9:0 PADDATA (VR4121 UM 20.3.9/20.3.10, VR4102 UM
   19.3.9/19.3.10). */
constexpr uint16_t kValid  = 0x8000u;
constexpr uint16_t kAdcMax = 1023u;

constexpr uint16_t kSyntheticHoldScans = 6u;

/* PIUSTBLREG D5:0 STABLE, both reset rows 0x0007 (VR4111 UM 20.3.4, VR4121 UM 20.3.4,
   VR4102 UM 19.3.4); PIUCMDREG D3:0 ADCMD, both reset rows 0x000F = "A/D converter standby
   mode request" (VR4111 UM 20.3.5, VR4121 UM 20.3.5, VR4102 UM 19.3.5). */
constexpr uint16_t kStblPowerOn = 0x0007u;
constexpr uint16_t kCmdPowerOn  = 0x000Fu;

struct Vr41xxPiuModel {
    uint32_t base;
    uint32_t size;
    uint32_t piu2_base;
    uint32_t piu2_size;
    uint16_t sivl_power_on;             /* PIUSIVLREG reset row                        */
    bool     has_penstp;                /* PIUCNTREG D14 PENSTP exists                 */
    bool     penstc_latched_by_penchg;  /* PIUCNTREG D13 PENSTC holds while PENCHGINTR */
};
}  /* namespace cerf_vr41xx_piu_detail */
