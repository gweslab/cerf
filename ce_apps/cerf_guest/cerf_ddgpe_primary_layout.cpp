#include "cerf_ddgpe_primary_layout.h"

#include "cerf_display_orientation.h"
#include "include/cerf_gpe.h"

#define CERF_PRIMARY_BIND_SLOTS 16

typedef struct {
    void*             lcl;
    CerfPrimaryLayout layout;
} CerfPrimaryBindSlot;

typedef struct {
    CRITICAL_SECTION    cs;
    CerfPrimaryBindSlot slots[CERF_PRIMARY_BIND_SLOTS];
} CerfPrimaryBinds;

static CerfPrimaryBinds s_binds;

void CerfPrimaryLayoutInit(void) {
    InitializeCriticalSection(&s_binds.cs);
}

void CerfPrimaryLayoutFor(int angle, int screen_w, int screen_h, int stride, int bytes_px,
                          CerfPrimaryLayout* out) {
    *out = cerfcore::CerfVirt::CerfRotatedLayoutFor(CerfDisplayOrientationQuarter((ULONG)angle), screen_w,
                                                    screen_h, stride, bytes_px);
}

static int CerfPrimarySlotOf(void* lcl) {
    int i;
    for (i = 0; i < CERF_PRIMARY_BIND_SLOTS; ++i)
        if (s_binds.slots[i].lcl == lcl) return i;
    return -1;
}

BOOL CerfPrimaryLayoutBind(void* lcl, const CerfPrimaryLayout* lay) {
    int slot;
    EnterCriticalSection(&s_binds.cs);
    slot = CerfPrimarySlotOf(lcl);
    if (slot < 0) slot = CerfPrimarySlotOf(NULL);
    if (slot >= 0) {
        s_binds.slots[slot].lcl    = lcl;
        s_binds.slots[slot].layout = *lay;
    }
    LeaveCriticalSection(&s_binds.cs);
    return slot >= 0;
}

void CerfPrimaryLayoutOf(void* lcl, CerfPrimaryLayout* out) {
    int slot;
    EnterCriticalSection(&s_binds.cs);
    slot = CerfPrimarySlotOf(lcl);
    if (slot >= 0) *out = s_binds.slots[slot].layout;
    LeaveCriticalSection(&s_binds.cs);
    if (slot < 0) CERF_FATAL("cerf_guest: DirectDraw primary without a bound layout");
}

void CerfPrimaryLayoutForget(void* lcl) {
    int slot;
    EnterCriticalSection(&s_binds.cs);
    slot = CerfPrimarySlotOf(lcl);
    if (slot >= 0) s_binds.slots[slot].lcl = NULL;
    LeaveCriticalSection(&s_binds.cs);
}

BOOL CerfPrimaryLayoutAnyBound(void) {
    int i;
    BOOL bound = FALSE;
    EnterCriticalSection(&s_binds.cs);
    for (i = 0; i < CERF_PRIMARY_BIND_SLOTS && !bound; ++i) bound = s_binds.slots[i].lcl != NULL;
    LeaveCriticalSection(&s_binds.cs);
    return bound;
}
