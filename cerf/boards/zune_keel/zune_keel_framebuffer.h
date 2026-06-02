#pragma once

#include <cstdint>

/* Must match zrecover's 240x320 splash (biWidth=240, biHeight=320): zrecover
   centers via (screenW-imgW)/2, (screenH-imgH)/2, so a 320x240 descriptor makes
   the y-base negative and the logo plots off-screen. kFbPa MUST stay below
   physfirst (0x80200000) or the kernel allocates over the buffer. */
namespace zune_keel {

constexpr uint32_t kFbPa    = 0x80100000u;
constexpr uint32_t kScreenW = 240u;
constexpr uint32_t kScreenH = 320u;
constexpr uint32_t kFbBytes = kScreenW * kScreenH * 2u;  /* RGB565 */

}  // namespace zune_keel
