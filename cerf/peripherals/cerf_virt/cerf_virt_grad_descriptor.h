#pragma once

#include "cerf_virt_blt_descriptor.h"   /* CerfBltSurface / CerfBltRect */

/* One flattened GRADIENT_RECT (ramp endpoints + clipped fill_rect + dst).
   Interpolation must match DeviceEmulator_lcd sub_17D3434/sub_17D1518 or it
   drifts off the stock pixels: 8-bit channel = high byte of a COLOR16 stepped
   at <<8 by floor(((endC16-startC16)<<8 << 32)/span). RECT_H/RECT_V only. */

#if defined(__cplusplus)
namespace CerfVirt {
#endif

/* Host validates this on read; mismatch = corrupt VA, halt rather than fill. */
const uint32_t kCerfGradMagic = 0x43475244u; /* 'CGRD' */

/* CerfGradDescriptor.axis — which axis the colour ramp runs along. */
const uint32_t kCerfGradAxisH = 0u; /* GRADIENT_FILL_RECT_H: colour varies with x */
const uint32_t kCerfGradAxisV = 1u; /* GRADIENT_FILL_RECT_V: colour varies with y */

typedef struct CerfGradDescriptor {
    uint32_t magic;
    uint32_t axis;          /* kCerfGradAxis* */
    int32_t  start_coord;   /* axis coord of the start (lower) vertex */
    int32_t  end_coord;     /* axis coord of the end vertex; span = end-start > 0 */
    /* COLOR16 (USHORT) channels at the ramp endpoints: [0]=R [1]=G [2]=B [3]=A.
       The 8-bit output channel is the high byte of the interpolated COLOR16. */
    uint16_t start_color[4];
    uint16_t end_color[4];
    CerfBltRect    fill_rect; /* device-space pixels to paint (already clipped) */
    CerfBltSurface dst;
} CerfGradDescriptor;

#if defined(__cplusplus)
}  /* namespace CerfVirt */
#endif
