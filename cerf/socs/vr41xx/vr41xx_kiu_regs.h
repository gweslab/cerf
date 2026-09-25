#pragma once

#include <cstdint>

namespace cerf_vr41xx_kiu_regs {

/* VR4102 UM Table 21-1, VR4121 UM Table 22-1, VR4111 UM Table 22-1 p459; the
   0x0B000180-0x0B00019F window is VR4111 UM Table 6-10 p170, VR4102 UM Table 5-10 p139,
   VR4121 UM Table 6-12 p178. */
constexpr uint32_t kBase = 0x0B000180u;

constexpr uint32_t kOffDat5    = 0x0Au;
constexpr uint32_t kOffScanRep = 0x10u;
constexpr uint32_t kOffScans   = 0x12u;
constexpr uint32_t kOffWks      = 0x14u;
constexpr uint32_t kOffWki      = 0x16u;
constexpr uint32_t kOffInt      = 0x18u;
constexpr uint32_t kOffRst      = 0x1Au;
constexpr uint32_t kOffGpen     = 0x1Cu;
constexpr uint32_t kOffScanLine = 0x1Eu;

/* KIUSCANREP D15 KEYEN, D9:4 STPREP, D3 SCANSTP, D2 SCANSTART, D1 ATSTP, D0 ATSCAN;
   D14:10 reserved R (VR4111 UM 22.2.2 p463, VR4102 UM 21.2.2 p425, VR4121 UM 22.2.2 p514). */
constexpr uint16_t kKeyen       = 0x8000u;
constexpr uint16_t kScanRepMask = 0x83FFu;
constexpr uint16_t kScanRepPowerOn = 0x0001u;   /* D0 ATSCAN reset row 1. */
constexpr uint16_t kScanStart   = 1u << 2;
constexpr uint16_t kScanStp     = 1u << 3;
constexpr uint16_t kAtStp       = 1u << 1;
constexpr uint16_t kAtScan      = 1u << 0;
constexpr uint32_t kStpRepShift = 4u;
constexpr uint16_t kStpRepBits  = 0x003Fu;

/* KIUSCANS SSTAT[1:0], R only (VR4111 UM 22.2.3 p465, VR4102 UM 21.2.3 p427,
   VR4121 UM 22.2.3 p516). */
constexpr uint16_t kSStatStopped   = 0x0000u;
constexpr uint16_t kSStatWaitKeyIn = 0x0001u;
constexpr uint16_t kSStatInterval  = 0x0002u;
constexpr uint16_t kSStatScanning  = 0x0003u;

/* KIUINT D2 KDATLOST, D1 KDATRDY, D0 SCANINT (VR4111 UM 22.2.6 p468, VR4102 UM 21.2.6 p431,
   VR4121 UM 22.2.6 p520). */
constexpr uint16_t kScanInt   = 1u << 0;
constexpr uint16_t kKDatRdy   = 1u << 1;
constexpr uint16_t kKDatLost  = 1u << 2;
constexpr uint16_t kIntMask   = 0x0007u;

/* KIURST D0, W (VR4111 UM 22.2.7 p469, VR4102 UM 21.2.7 p432, VR4121 UM 22.2.7 p521). */
constexpr uint16_t kKiuRst      = 0x0001u;

/* KIUWKS D14:10 T3CNT, D9:5 T2CNT, D4:0 T1CNT, each (field + 1) x 30 us, 00000 RFU, D14:0
   reset 1 (VR4111 UM 22.2.4 p466, VR4102 UM 21.2.4 p429, VR4121 UM 22.2.4 p518). KIUWKI
   WINTVL(9:0) x 30 us, 0 = No Wait (22.2.5 p467 / p430 / p519). */
constexpr uint16_t kWksMask     = 0x7FFFu;
constexpr uint16_t kWksReset    = 0x7FFFu;
constexpr uint16_t kCntBits     = 0x001Fu;
constexpr uint32_t kT2CntShift  = 5u;
constexpr uint32_t kT3CntShift  = 10u;
constexpr uint16_t kWintvlBits  = 0x03FFu;
constexpr uint32_t kTimeUnitUs  = 30u;

/* SCANLINE LINE[1:0]: 00 twelve pins, 01 ten, 10 eight, 11 SCAN pins are output ports
   (VR4111 UM 22.2.9 p472, VR4102 UM 21.2.9 p434, VR4121 UM 22.2.9 p524). KSCAN[2n] and
   KSCAN[2n+1] land in KIUDATn (22.2.1 p461). */
constexpr uint16_t kScanLineMask = 0x0003u;
constexpr uint16_t kScanLineNone = 0x0003u;

constexpr uint16_t kGpenMask = 0x0FFFu;

}
