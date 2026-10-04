#include <windows.h>

#include "cerf_cleartype_pump.h"
#include "cerf_regs_map.h"
#include "cerf_shell_watch.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_fb_regs.h"

#ifndef SPI_SETFONTSMOOTHING
#define SPI_SETFONTSMOOTHING 0x004B
#endif
#ifndef SPIF_UPDATEINIFILE
#define SPIF_UPDATEINIFILE 0x0001
#endif
#ifndef SPIF_SENDCHANGE
#define SPIF_SENDCHANGE 0x0002
#endif

typedef BOOL (WINAPI *PFN_SystemParametersInfoW)(UINT, UINT, PVOID, UINT);
typedef BOOL (WINAPI *PFN_InvalidateRect)(HWND, const RECT*, BOOL);

typedef struct {
    volatile ULONG*           regs;
    PFN_SystemParametersInfoW spi;
    PFN_InvalidateRect        invalidate;
    ULONG                     seen;
    BOOL                      ready;
    BOOL                      dead;
} CerfCtState;

static CerfCtState s_ct;

static CerfCtState* Ct(void) { return &s_ct; }

static BOOL CerfCtResolve(CerfCtState* c) {
    HMODULE h = LoadLibraryW(L"coredll.dll");
    if (!h) return FALSE;
    c->spi = (PFN_SystemParametersInfoW)GetProcAddressW(h, L"SystemParametersInfoW");
    c->invalidate = (PFN_InvalidateRect)GetProcAddressW(h, L"InvalidateRect");
    return c->spi != NULL && c->invalidate != NULL;
}

static void CerfCtApply(CerfCtState* c, BOOL on) {
    HKEY  key;
    DWORD enabled = on ? 1u : 0u;
    BOOL  ok;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\GDI\\ClearTypeSettings", 0, NULL, 0,
                        KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"Enabled", 0, REG_DWORD, (LPBYTE)&enabled, sizeof(enabled));
        RegCloseKey(key);
    }
    ok = c->spi(SPI_SETFONTSMOOTHING, on ? TRUE : FALSE, NULL,
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    CERF_LOG_X("cerf_guest: cleartype set", enabled);
    CERF_LOG_X("cerf_guest: cleartype SystemParametersInfo result", ok);
    c->invalidate(NULL, NULL, TRUE);
}

extern "C" void CerfClearTypeTick(void) {
    CerfCtState* c = Ct();
    ULONG mode;

    if (c->dead) return;
    if (!CerfShellWatchIsUp()) return;

    if (!c->ready) {
        c->ready = TRUE;
        c->regs = (volatile ULONG*)CerfMapRegsPage(
            g_CerfVirtBase + CerfVirt::kFramebufferRegsOffset,
            CerfVirt::kFramebufferRegsSize);
        if (!c->regs) {
            CERF_LOG("cerf_guest: cleartype map FAILED");
            c->dead = TRUE;
            return;
        }
        if (!CerfCtResolve(c)) {
            CERF_LOG("cerf_guest: cleartype no SystemParametersInfoW - disabled");
            c->dead = TRUE;
            return;
        }
        c->seen = CerfVirt::kFbClearTypeDefault;
    }

    mode = c->regs[CerfVirt::kFbRegClearType / 4];
    if (mode == c->seen) return;
    c->seen = mode;
    if (mode == CerfVirt::kFbClearTypeOn)
        CerfCtApply(c, TRUE);
    else if (mode == CerfVirt::kFbClearTypeOff)
        CerfCtApply(c, FALSE);
}
