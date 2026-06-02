#pragma once

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned int   uint32_t;
typedef int            int32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;
#else
#include <cstdint>
#endif

/* Shared host<->guest GPE blit descriptor. Do NOT add a pConvert field — it is
   a driver member-fn pointer that derefs to garbage host-side; the host converts
   from src_fmt/dst_fmt itself. */

#if defined(__cplusplus)
namespace CerfVirt {
#endif

/* Host validates this on read; mismatch = corrupt VA, halt rather than blit. */
const uint32_t kCerfBltMagic = 0x43424C54u; /* 'CBLT' */

/* CerfBltSurface.format — EGPEFormat (gpe.h). */
const uint32_t kCerfFmt1Bpp  = 0u;
const uint32_t kCerfFmt2Bpp  = 1u;
const uint32_t kCerfFmt4Bpp  = 2u;
const uint32_t kCerfFmt8Bpp  = 3u;
const uint32_t kCerfFmt16Bpp = 4u;
const uint32_t kCerfFmt24Bpp = 5u;
const uint32_t kCerfFmt32Bpp = 6u;

/* CerfBltSurface.rotate — DMDO_* (winddi.h), only when is_rotate. */
const uint32_t kCerfRotate0   = 0u;
const uint32_t kCerfRotate90  = 1u;
const uint32_t kCerfRotate180 = 2u;
const uint32_t kCerfRotate270 = 3u;

typedef struct CerfBltRect {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} CerfBltRect;

typedef struct CerfBltSurface {
    uint32_t buffer;    /* guest VA, or FB-region PA when is_fb_pa */
    int32_t  stride;    /* bytes per row */
    uint32_t format;    /* kCerfFmt* */
    uint32_t is_fb_pa;  /* 1 = buffer is an FB-region PA; 0 = guest VA */
    uint32_t is_rotate; /* 1 = coordinate-addressed rotated surface */
    uint32_t rotate;    /* kCerfRotate* when is_rotate */
    uint32_t screen_w;  /* physical screen width  (rotated addressing) */
    uint32_t screen_h;  /* physical screen height (rotated addressing) */
    /* Actual channel masks from GPEFormat::m_pPalette — the reference uses the
       surface's real masks, never an assumed-per-format set. mask[0..2]=R,G,B
       (and mask[3]=A if pal_entries==4). pal_entries: 3=RGB, 4=ARGB, else indexed
       (mask[] = 0). */
    uint32_t pal_entries;
    uint32_t mask[4];
} CerfBltSurface;

typedef struct CerfBltDescriptor {
    uint32_t magic;
    uint32_t rop4;           /* (background_rop3 << 8) | foreground_rop3 */
    uint32_t blt_flags;      /* winddi.h BLT_* (STRETCH/TRANSPARENT/ALPHABLEND/...) */
    uint32_t solid_color;    /* solid src/brush seed; also the BLT_TRANSPARENT key */
    uint32_t blend_function; /* BLENDFUNCTION packed: Op|Flags<<8|SrcConstA<<16|AlphaFmt<<24 */
    uint32_t i_mode;         /* COLORONCOLOR/BILINEAR/HALFTONE (host renders nearest) */
    uint32_t x_positive;     /* iterate dst left->right when 1, else mirrored */
    uint32_t y_positive;     /* iterate dst top->bottom when 1, else mirrored */

    uint32_t has_src;
    uint32_t has_mask;
    uint32_t has_brush;
    uint32_t has_clip;
    uint32_t lookup_va;      /* pLookup table guest VA (dst-format colors); 0 = none */
    uint32_t convert_active; /* 1 = apply src_fmt->dst_fmt conversion (pConvert present) */

    CerfBltRect dst_rect;
    CerfBltRect src_rect;
    CerfBltRect mask_rect;
    CerfBltRect clip_rect;

    CerfBltSurface dst;
    CerfBltSurface src;
    CerfBltSurface mask;
    CerfBltSurface brush;

    int32_t  brush_ptl_x;    /* pptlBrush origin; brush_has_ptl gates validity */
    int32_t  brush_ptl_y;
    uint32_t brush_has_ptl;  /* 1 = pptlBrush was supplied */
    uint32_t brush_width;    /* pBrush tile width  (pattern wrap modulus) */
    uint32_t brush_height;   /* pBrush tile height */
} CerfBltDescriptor;

#if defined(__cplusplus)
}  /* namespace CerfVirt */
#endif
