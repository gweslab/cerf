#pragma once

#include "rom_image_parse.h"

#include <cstdint>
#include <span>

namespace cerf::rom_image_parse {

/* symbol_mk500 dump.bin 0x00080000 partition table: 0x40-byte slots, 0x20-byte
   NUL-terminated ASCII name, then start word (0x8000 | erase block) and block
   count; "Monitor" 0, "Windows CE" 6, "Platform" 0x80, "Application" 0xA0. */
constexpr size_t kSymbolPartTableOff  = 0x00080000u;
constexpr size_t kSymbolPartEntrySize = 0x40u;
constexpr size_t kSymbolPartNameBytes = 0x20u;
constexpr size_t kSymbolPartSlots     = 32u;

/* symbol_mk500 dump.bin "Windows CE" block 6 * 0x40000 == 0x00180000, whose
   +0x40 ECEC and ROMHDR physfirst 0x80180000 place the XIP; DL_FS3.00 volume
   headers recur at every 0x40000 boundary from 0x02000000. */
constexpr uint32_t kSymbolFlashBlockBytes = 0x40000u;

struct SymbolFlashOsXip {
    size_t   data_off    = 0;
    uint32_t flat_size   = 0;
    uint32_t base_va     = 0;
    uint32_t flash_va    = 0;
    uint32_t part_blocks = 0;
    size_t   table_off   = 0;
};

bool SymbolFlashLocateOsXip(std::span<const uint8_t> raw, SymbolFlashOsXip& out);

}  /* namespace cerf::rom_image_parse */
