#pragma once

#define CERF_VERSION_MAJOR 8
#define CERF_VERSION_MINOR 1
#define CERF_VERSION_PATCH 0

#define CERF_VERSION_BUILD      0

/* Windows SDK verrsrc.h VS_FIXEDFILEINFO: dwFileVersionLS packs two version
   components per DWORD ("e.g. 0x00000031 = 0.31"), so a VERSIONINFO component
   holds 16 bits and truncates past 65535. */
#define CERF_VERSION_BUILD_WORD 0
#define CERF_VERSION_DATE       ""
#define CERF_VERSION_SHA        ""

#define CERF_STR_(x)    #x
#define CERF_STR(x)     CERF_STR_(x)

#if CERF_VERSION_PATCH
#define CERF_VERSION_STR         \
    CERF_STR(CERF_VERSION_MAJOR) "." \
    CERF_STR(CERF_VERSION_MINOR) "." \
    CERF_STR(CERF_VERSION_PATCH)
#else
#define CERF_VERSION_STR         \
    CERF_STR(CERF_VERSION_MAJOR) "." \
    CERF_STR(CERF_VERSION_MINOR)
#endif

#define CERF_VERSION_LABEL "v" CERF_VERSION_STR

#if CERF_VERSION_BUILD
#define CERF_VERSION_BUILD_STR \
    "build " CERF_STR(CERF_VERSION_BUILD) ", " \
    CERF_VERSION_DATE ", " CERF_VERSION_SHA
#define CERF_VERSION_DISPLAY_STR   CERF_VERSION_STR  " ("  CERF_VERSION_BUILD_STR  ")"
#else
#define CERF_VERSION_BUILD_STR     ""
#define CERF_VERSION_DISPLAY_STR   CERF_VERSION_STR
#endif
