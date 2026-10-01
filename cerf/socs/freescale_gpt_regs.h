#pragma once

#include <cstdint>

namespace cerf_freescale_gpt_detail {

inline constexpr uint32_t kSize = 0x00004000u;

/* MCIMX31RM Table 34-3 / MCIMX51RM Table 36-3. */
inline constexpr uint32_t kOffGptcr   = 0x00u;
inline constexpr uint32_t kOffGptpr   = 0x04u;
inline constexpr uint32_t kOffGptsr   = 0x08u;
inline constexpr uint32_t kOffGptir   = 0x0Cu;
inline constexpr uint32_t kOffGptocr1 = 0x10u;
inline constexpr uint32_t kOffGptocr2 = 0x14u;
inline constexpr uint32_t kOffGptocr3 = 0x18u;
inline constexpr uint32_t kOffGpticr1 = 0x1Cu;
inline constexpr uint32_t kOffGpticr2 = 0x20u;
inline constexpr uint32_t kOffGptcnt  = 0x24u;

/* MCIMX31RM Table 34-6 / MCIMX51RM Table 36-5 GPTCR. */
inline constexpr uint32_t kGptcrEn       = 1u << 0;
inline constexpr uint32_t kGptcrEnmod    = 1u << 1;
inline constexpr uint32_t kGptcrWaiten   = 1u << 3;
inline constexpr uint32_t kGptcrDozen    = 1u << 4;
inline constexpr uint32_t kGptcrStopen   = 1u << 5;
inline constexpr uint32_t kGptcrClksrcSh = 6u;
inline constexpr uint32_t kGptcrFrr      = 1u << 9;
inline constexpr uint32_t kGptcrSwr      = 1u << 15;
inline constexpr uint32_t kGptcrStored   = 0x000003FFu;
inline constexpr uint32_t kGptcrPinModes = 0xFFFF0000u;

/* MCIMX31RM Table 34-8 / MCIMX51RM Table 36-7 GPTSR, Table 34-9 / 36-8 GPTIR. */
inline constexpr uint32_t kGptOf1        = 1u << 0;
inline constexpr uint32_t kGptRov        = 1u << 5;
inline constexpr uint32_t kGptStatusMask = 0x3Fu;

/* MCIMX31RM Table 34-7 / MCIMX51RM Table 36-6 GPTPR. */
inline constexpr uint32_t kGptprMask = 0xFFFu;

/* MCIMX31RM Table 34-3 / MCIMX51RM Figure 36-7: GPTOCRn reset. */
inline constexpr uint32_t kOcrReset = 0xFFFFFFFFu;

enum class GptClockInput : uint8_t { kNone, kIpg, kHighfreq, kLowfreq, kPad, kUndefined };

}
