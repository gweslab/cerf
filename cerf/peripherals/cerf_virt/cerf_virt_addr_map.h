#pragma once

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned int uint32_t;
#else
#include <cstdint>
#endif

/* DO NOT move kBaseAddr outside 0xD0000000-0xDFFFFFFF: collides with
   iPaq SDRAM (0xC0000000), SA1110 zero-bank (0xE0000000), and SoC MMIO
   blocks at 0xA0000000-0xBFFFFFFF. */

namespace CerfVirt {

const uint32_t kBaseAddr  = 0xD0000000u;
const uint32_t kTotalSize = 0x10000000u;

const uint32_t kRegsBase = kBaseAddr;
const uint32_t kRegsSize = 0x10000u;

const uint32_t kDebugTxBase = kRegsBase + 0x0000u;
const uint32_t kDebugTxSize = 0x1000u;

const uint32_t kFramebufferRegsBase = kRegsBase + 0x1000u;
const uint32_t kFramebufferRegsSize = 0x1000u;

const uint32_t kGpeCmdBase = kRegsBase + 0x2000u;
const uint32_t kGpeCmdSize = 0x1000u;

const uint32_t kFramebufferMemBase = kBaseAddr + 0x00100000u;
const uint32_t kFramebufferMemSize = 0x02000000u;

}  /* namespace CerfVirt */
