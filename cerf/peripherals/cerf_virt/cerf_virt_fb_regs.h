#pragma once

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned int uint32_t;
#else
#include <cstdint>
#endif

namespace CerfVirt {

const uint32_t kFbRegWidth       = 0x00u;
const uint32_t kFbRegHeight      = 0x04u;
const uint32_t kFbRegBpp         = 0x08u;
const uint32_t kFbRegStride      = 0x0Cu;
const uint32_t kFbRegSizeBytes   = 0x10u;
const uint32_t kFbRegMemBasePa   = 0x14u;
const uint32_t kFbRegPresent     = 0x18u;
const uint32_t kFbRegMemSizeTotal = 0x1Cu;  /* total host-backed region bytes
                                               (kFramebufferMemSize); the driver
                                               carves DDraw video memory from the
                                               span past the primary surface. */

}  /* namespace CerfVirt */
