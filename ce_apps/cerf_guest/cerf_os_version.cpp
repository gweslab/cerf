#include "cerf_os_version.h"

#define CERF_OS_MAJOR_WHEN_UNKNOWN 5u
#define CERF_WP7_MAJOR_VERSION     7u
#define CERF_WP7_MINOR_VERSION     10u

static const OSVERSIONINFOW* CerfOsVersion(void) {
    static OSVERSIONINFOW s_version;
    static BOOL           s_read = FALSE;
    if (!s_read) {
        OSVERSIONINFOW v;
        memset(&v, 0, sizeof(v));
        v.dwOSVersionInfoSize = sizeof(v);
        if (!GetVersionExW(&v)) v.dwMajorVersion = CERF_OS_MAJOR_WHEN_UNKNOWN;
        s_version = v;
        s_read    = TRUE;
    }
    return &s_version;
}

extern "C" ULONG CerfOsMajor(void) { return CerfOsVersion()->dwMajorVersion; }

extern "C" ULONG CerfOsMinor(void) { return CerfOsVersion()->dwMinorVersion; }

extern "C" BOOL CerfIsWp7(void) {
    return CerfOsMajor() == CERF_WP7_MAJOR_VERSION && CerfOsMinor() >= CERF_WP7_MINOR_VERSION;
}
