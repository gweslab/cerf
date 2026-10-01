#pragma once

#include <cstdint>

/* Freescale SDMA register map and buffer-descriptor layout, identical on i.MX31
   (MCIMX31RM Ch 40) and i.MX51 (MCIMX51RM Ch 52). Divergent registers (EVT_MIRROR,
   CHNENBL window) belong to the concretes. */
namespace cerf_freescale_sdma_detail {

constexpr uint32_t kSdmaSize = 0x00004000u;

/* Registers at the SAME offset on i.MX31 (Table 40-10) and i.MX51 (Table 52-9). */
constexpr uint32_t kOffMc0ptr      = 0x000u;
constexpr uint32_t kOffIntr        = 0x004u;
constexpr uint32_t kOffStopStat    = 0x008u;
constexpr uint32_t kOffHstart      = 0x00Cu;
constexpr uint32_t kOffEvtovr      = 0x010u;
constexpr uint32_t kOffDspovr      = 0x014u;
constexpr uint32_t kOffHostovr     = 0x018u;
constexpr uint32_t kOffEvtpend     = 0x01Cu;
constexpr uint32_t kOffReset       = 0x024u;
constexpr uint32_t kOffEvterr      = 0x028u;
constexpr uint32_t kOffIntrmask    = 0x02Cu;
constexpr uint32_t kOffPsw         = 0x030u;
constexpr uint32_t kOffEvterrdbg   = 0x034u;
constexpr uint32_t kOffConfig      = 0x038u;
constexpr uint32_t kOffOnceEnb     = 0x040u;
constexpr uint32_t kOffOnceData    = 0x044u;
constexpr uint32_t kOffOnceInstr   = 0x048u;
constexpr uint32_t kOffOnceStat    = 0x04Cu;
constexpr uint32_t kOffOnceCmd     = 0x050u;
constexpr uint32_t kOffIllinstaddr = 0x058u;
constexpr uint32_t kOffChn0addr    = 0x05Cu;
constexpr uint32_t kOffXtrigConf1  = 0x070u;
constexpr uint32_t kOffXtrigConf2  = 0x074u;
constexpr uint32_t kOffChnpriBase  = 0x100u;   /* CHNPRIn, n=0..31, both SoCs */
constexpr uint32_t kChannelCount   = 32u;
constexpr uint32_t kMaxDmaEvents   = 48u;      /* MCIMX51RM Table 52-9; MCIMX31RM Table 40-10 has 32 */

/* Reset values, identical on both SoCs (MCIMX31RM Table 40-10 / MCIMX51RM Table 52-9). */
constexpr uint32_t kResetDspovr      = 0xFFFFFFFFu;
constexpr uint32_t kResetConfig      = 0x00000003u;
constexpr uint32_t kResetOnceStat    = 0x0000E000u;
constexpr uint32_t kResetIllinstaddr = 0x00000001u;
constexpr uint32_t kResetChn0addr    = 0x00000050u;

/* RESET register bit 0 = SDMA software reset (self-clearing). */
constexpr uint32_t kResetBitReset = 1u << 0;

/* BD word0 = count[15:0] | status[23:16] | command[31:24]: MCIMX51RM Table 52-96;
   Linux drivers/dma/imx-sdma.c (sdma_mode_count, BD_* on fsl,imx31-sdma and
   fsl,imx51-sdma); kBdExtd per cspddk DDKSdmaSetBufDesc OR-mask 0x810000. */
constexpr uint32_t kBdDone       = 1u << 16;   /* D */
constexpr uint32_t kBdWrap       = 1u << 17;   /* W */
constexpr uint32_t kBdCont       = 1u << 18;
constexpr uint32_t kBdIntr       = 1u << 19;   /* I */
constexpr uint32_t kBdError      = 1u << 20;   /* R */
constexpr uint32_t kBdExtd       = 1u << 23;
constexpr uint32_t kCcbStride    = 16u;
constexpr uint32_t kCcbBaseBdOff = 4u;
constexpr uint32_t kMaxBdWalk    = 256u;

}  /* namespace cerf_freescale_sdma_detail */
