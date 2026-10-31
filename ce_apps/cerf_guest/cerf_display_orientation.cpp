#include "cerf_display_orientation.h"

#define CERF_DEVMODEW_SIZE 192u
#define CERF_DMDO_OFFSET   188u

LONG CerfDisplayOrientationCall(CerfChangeDisplaySettingsExFn cds, DWORD fields, DWORD dmdo,
                                DWORD flags, DWORD* out_dmdo) {
    DWORD     buf[CERF_DEVMODEW_SIZE / sizeof(DWORD)];
    DEVMODEW* dm = (DEVMODEW*)buf;
    LONG      r;
    memset(buf, 0, sizeof(buf));
    dm->dmSize   = (WORD)CERF_DEVMODEW_SIZE;
    dm->dmFields = fields;
    buf[CERF_DMDO_OFFSET / sizeof(DWORD)] = dmdo;
    r = cds(NULL, dm, NULL, flags, NULL);
    if (out_dmdo) *out_dmdo = buf[CERF_DMDO_OFFSET / sizeof(DWORD)];
    return r;
}

static const ULONG kCerfDmdoByQuarter[4] = { DMDO_0, DMDO_90, DMDO_180, DMDO_270 };

ULONG CerfDisplayOrientationQuarter(ULONG dmdo) {
    ULONG quarter;
    for (quarter = 1u; quarter < 4u; ++quarter)
        if (kCerfDmdoByQuarter[quarter] == dmdo) return quarter;
    return 0u;
}

ULONG CerfDisplayOrientationOfQuarter(ULONG quarter) {
    return kCerfDmdoByQuarter[quarter & 3u];
}

BOOL CerfDisplayOrientationSideways(ULONG dmdo) {
    return (CerfDisplayOrientationQuarter(dmdo) & 1u) != 0u;
}
