#pragma once

#include <cstdint>

namespace S3C2410IisRegs {

/* S3C2410A User Manual, printed pp. 21-5..21-8 "IIS-BUS INTERFACE SPECIAL
   REGISTERS": IISCON at 0x55000000, IISMOD 0x55000004, IISPSR 0x55000008,
   IISFCON 0x5500000C, IISFIFO 0x55000010. */
constexpr uint32_t kBase = 0x55000000u;
constexpr uint32_t kSpan = 0x14u;

constexpr uint32_t kOffCon  = 0x00u;
constexpr uint32_t kOffMod  = 0x04u;
constexpr uint32_t kOffPsr  = 0x08u;
constexpr uint32_t kOffFcon = 0x0Cu;
constexpr uint32_t kOffFifo = 0x10u;

/* S3C2410A User Manual, printed p. 21-5 IISCON. */
constexpr uint32_t kConWritable  = 0x0000003Fu;
constexpr uint32_t kConReset     = 0x00000100u;
constexpr uint32_t kConLrIndex   = 1u << 8;
constexpr uint32_t kConTxFifoRdy = 1u << 7;
constexpr uint32_t kConTxDmaReq  = 1u << 5;
constexpr uint32_t kConRxDmaReq  = 1u << 4;
constexpr uint32_t kConTxIdle    = 1u << 3;
constexpr uint32_t kConPscEnable = 1u << 1;
constexpr uint32_t kConEnable    = 1u << 0;

/* S3C2410A User Manual, printed p. 21-6 IISMOD. */
constexpr uint32_t kModWritable = 0x000001FFu;
constexpr uint32_t kModSlave    = 1u << 8;
constexpr uint32_t kModTransmit = 1u << 7;
constexpr uint32_t kMod16Bit    = 1u << 3;
constexpr uint32_t kMod384fs    = 1u << 2;

/* S3C2410A User Manual, printed p. 21-7 IISPSR and Figure 21-1 printed p. 21-2. */
constexpr uint32_t kPsrWritable = 0x000003FFu;
constexpr uint32_t kPsrAShift   = 5u;
constexpr uint32_t kPsrFieldMask = 0x1Fu;

/* S3C2410A User Manual, printed p. 21-8 IISFCON. */
constexpr uint32_t kFconWritable   = 0x0000F000u;
constexpr uint32_t kFconTxDmaMode  = 1u << 15;
constexpr uint32_t kFconRxDmaMode  = 1u << 14;
constexpr uint32_t kFconTxEnable   = 1u << 13;
constexpr uint32_t kFconRxEnable   = 1u << 12;
constexpr uint32_t kFconTxCntShift = 6u;

/* S3C2410A User Manual, printed p. 21-4, Table 21-1 "CODEC clock (CODECLK = 256
   or 384fs)". */
constexpr uint32_t kCodecClk256 = 256u;
constexpr uint32_t kCodecClk384 = 384u;

/* S3C2410A User Manual, printed p. 21-3: the transmitter sends one word per
   IISLRCK phase, two FIFO entries per 16-bit stereo frame. */
constexpr uint32_t kEntriesPerFrame = 2u;

}
