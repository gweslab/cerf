#include <windows.h>
#include "cerf_cursor.h"
#include "cerf_regs_map.h"
#include <string.h>

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"
#define CERF_CUR_KICK         0x004u

#define CERF_CUR_MAX_DIM      64u
#define CERF_CUR_MAX_STRIDE   ((CERF_CUR_MAX_DIM + 7u) / 8u)
#define CERF_CUR_BITS_BYTES   (CERF_CUR_MAX_STRIDE * CERF_CUR_MAX_DIM * 2u)

typedef struct {
    DWORD visible;
    DWORD cx;
    DWORD cy;
    DWORD xhot;
    DWORD yhot;
    DWORD stride;
    BYTE  bits[CERF_CUR_BITS_BYTES];
} CerfCursorDesc;

typedef struct {
    volatile ULONG* regs;
    CerfCursorDesc* desc;
} CerfCursorState;

static CerfCursorState s_cur;

static CerfCursorState* Cur(void) { return &s_cur; }

static BOOL CerfMapCursorRegs(void) {
    CerfCursorState* c = Cur();
    if (!c->regs)
        c->regs = (volatile ULONG*)CerfMapRegsPage(
            g_CerfVirtBase + CerfVirt::kCursorOffset, CerfVirt::kCursorSize);
    if (!c->desc)
        c->desc = (CerfCursorDesc*)CerfMapRegsPage(
            g_CerfVirtBase + CerfVirt::kCurStageOffset, CerfVirt::kCurStageSize);
    return c->regs != NULL && c->desc != NULL;
}

extern "C" void CerfPublishCursor(const void* mask_bits, int stride,
                                  int cx, int cy, int xhot, int yhot, BOOL visible) {
    if (!CerfMapCursorRegs()) return;
    CerfCursorDesc* d = Cur()->desc;

    DWORD dst_stride = (cx > 0) ? (DWORD)((cx + 7) / 8) : 0u;

    d->cx     = (DWORD)cx;
    d->cy     = (DWORD)cy;
    d->xhot   = (DWORD)xhot;
    d->yhot   = (DWORD)yhot;
    d->stride = dst_stride;
    d->visible = (visible && mask_bits && cx > 0 && cy > 0 &&
                  dst_stride <= CERF_CUR_MAX_STRIDE &&
                  (DWORD)cy <= CERF_CUR_MAX_DIM) ? 1u : 0u;

    if (d->visible) {
        const BYTE* src = (const BYTE*)mask_bits;
        for (int row = 0; row < cy; ++row) {
            memcpy(d->bits + (DWORD)row * dst_stride,
                   src + row * stride, dst_stride);
            memcpy(d->bits + ((DWORD)cy + (DWORD)row) * dst_stride,
                   src + (cy + row) * stride, dst_stride);
        }
    }
    CERF_LOG_X_DEV("cerf_guest: cursor publish cy", (DWORD)cy);

    Cur()->regs[CERF_CUR_KICK / 4] = 1u;
}
