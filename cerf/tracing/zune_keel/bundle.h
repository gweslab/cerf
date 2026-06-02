#pragma once

#include <cstdint>

/* Bundle CRC32 for zune_keel (Microsoft Zune 30, Pyxis/Keel BSP, CE 5.0).
   Logged by RomParserService over the concatenated raw bytes of nk.bin +
   EBoot.bin + recovery.bin. Trace files in this directory key off this
   value via TraceManager::RegisterForBundle. */
inline constexpr uint32_t kZuneKeelBundleCrc32 = 0xBCFC11B6u;
