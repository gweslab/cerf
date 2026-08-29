#pragma once

#include <cstdint>

/* Bundle CRC32 for falcon_4220 (Datalogic Falcon 4220, PC3xx / Askey PC320
   board, Intel XScale PXA255, Windows CE .NET 4.2). Logged by
   RomParserService over the ROM's concatenated raw bytes; trace files in
   this directory key off it via TraceManager::RegisterForBundle. */
inline constexpr uint32_t kFalcon4220BundleCrc32 = 0x47F7D31Cu;
