#pragma once

#include <cstdint>

namespace vr4121_bcu {

constexpr uint32_t kOffCnt1    = 0x00u;
constexpr uint32_t kOffRamSize = 0x06u;
constexpr uint32_t kOffCnt3    = 0x16u;

constexpr uint16_t kCnt1Rom64  = 0x8000u;
constexpr uint16_t kCnt1Dram64 = 0x4000u;
constexpr uint16_t kCnt1Rd64d  = 0x0004u;

constexpr uint16_t kCnt3ExtDram64 = 0x4000u;
constexpr uint16_t kCnt3ExtMem    = 0x0800u;
constexpr uint16_t kCnt3ExtFields = 0xF800u;

constexpr uint16_t kRamSizeWmask = 0x7777u;

constexpr uint32_t RamSizeCode(uint16_t ramsize, uint32_t bank) {
    return (ramsize >> (4u * bank)) & 0x7u;
}

}
