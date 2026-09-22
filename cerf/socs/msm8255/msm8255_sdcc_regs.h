#pragma once

#include <cstdint>

namespace cerf_msm8255_sdcc_detail {

constexpr uint32_t kPower      = 0x000u;
constexpr uint32_t kClock      = 0x004u;
constexpr uint32_t kArgument   = 0x008u;
constexpr uint32_t kCommand    = 0x00Cu;
constexpr uint32_t kResponse0  = 0x014u;
constexpr uint32_t kResponse1  = 0x018u;
constexpr uint32_t kResponse2  = 0x01Cu;
constexpr uint32_t kResponse3  = 0x020u;
constexpr uint32_t kDataTimer  = 0x024u;
constexpr uint32_t kDataLength = 0x028u;
constexpr uint32_t kDataCtrl   = 0x02Cu;
constexpr uint32_t kFifo       = 0x080u;
constexpr uint32_t kFifoBytes  = 16u * 4u;
constexpr uint32_t kStatus     = 0x034u;
constexpr uint32_t kClear      = 0x038u;
constexpr uint32_t kMask0      = 0x03Cu;
constexpr uint32_t kMask1      = 0x040u;

constexpr uint32_t kCmdIndex    = 0x0000003Fu;
constexpr uint32_t kCmdResponse = 1u << 6;
constexpr uint32_t kCmdLongRsp  = 1u << 7;
constexpr uint32_t kCmdEnable   = 1u << 10;
constexpr uint32_t kCmdProgEna  = 1u << 11;
constexpr uint32_t kCmdDatCmd   = 1u << 12;

constexpr uint32_t kCmdModelled =
    kCmdIndex | kCmdResponse | kCmdLongRsp | kCmdEnable | kCmdProgEna |
    kCmdDatCmd;

constexpr uint32_t kDataCtrlEnable         = 1u << 0;
constexpr uint32_t kDataCtrlDirection      = 1u << 1;
constexpr uint32_t kDataCtrlDmaEnable      = 1u << 3;
constexpr uint32_t kDataCtrlBlockSize      = 0xFFF0u;
constexpr uint32_t kDataCtrlBlockSizeShift = 4u;

constexpr uint32_t kDataLengthBits = 25u;
constexpr uint32_t kDataLengthMax  = (1u << kDataLengthBits) - 1u;

constexpr uint32_t kDataCtrlModelled =
    kDataCtrlEnable | kDataCtrlDirection | kDataCtrlDmaEnable |
    kDataCtrlBlockSize;

constexpr uint32_t kStatusCmdTimeout   = 1u << 2;
constexpr uint32_t kStatusCmdRespEnd   = 1u << 6;
constexpr uint32_t kStatusCmdSent      = 1u << 7;
constexpr uint32_t kStatusDataEnd      = 1u << 8;
constexpr uint32_t kStatusDataBlockEnd = 1u << 10;
constexpr uint32_t kStatusProgDone     = 1u << 23;

constexpr uint32_t kStatusLatchable =
    kStatusCmdTimeout | kStatusCmdRespEnd | kStatusCmdSent | kStatusProgDone |
    kStatusDataEnd | kStatusDataBlockEnd;

constexpr uint32_t kClearStaticMask =
    (1u << 0) | (1u << 1) | (1u << 2) | (1u << 3) | (1u << 4) | (1u << 5) |
    (1u << 6) | (1u << 7) | (1u << 8) | (1u << 9) | (1u << 10) | (1u << 22) |
    (1u << 23) | (1u << 24) | (1u << 25) | (1u << 26);

constexpr uint32_t kQuiescent = 0u;

constexpr uint32_t kPowerWritable = 0x00000041u;
constexpr uint32_t kClockWritable = 0x0000FF00u;
constexpr uint32_t kMaskWritable  = 0x1FFFFFFFu;

constexpr uint32_t kUngroundedPowerOn = 0u;

}  // namespace cerf_msm8255_sdcc_detail
