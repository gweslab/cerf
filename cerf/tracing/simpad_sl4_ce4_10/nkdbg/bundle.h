#pragma once

#include <cstdint>

/* CRC32 of the simpad_sl4_ce4_10 bundle (S842-SI-INT-152-SL4.nb0), computed
   over RomParserService::Loaded()[i].raw the same way TraceManager does
   (zlib CRC32). Confirm against the "[TRACE] bundle CRC32 = 0x..." log line
   on first boot; if it differs, update this constant. */
constexpr uint32_t kSimpadSl4Ce4BundleCrc32 = 0xF4D766C1u;
