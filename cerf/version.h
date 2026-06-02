#pragma once

#define CERF_VERSION_MAJOR 3
#define CERF_VERSION_MINOR 0
#define CERF_VERSION_PATCH 0

// 4th VERSIONINFO field (WORD, 0-65535). build.yml stamps this with the CI
// run number; stays 0 for local builds. VERSIONINFO fields are 16-bit, which
// is why CI freshness info (a timestamp) lives in the DISPLAY strings below
// instead of being crammed into a numeric field.
#define CERF_VERSION_BUILD 0

#define CERF_STR_(x)    #x
#define CERF_STR(x)     CERF_STR_(x)
#define CERF_WSTR__(x)  L##x
#define CERF_WSTR_(x)   CERF_WSTR__(x)
#define CERF_WSTR(x)    CERF_WSTR_(CERF_STR(x))

#define CERF_VERSION_STR  \
    CERF_STR(CERF_VERSION_MAJOR)  "." \
    CERF_STR(CERF_VERSION_MINOR)  "." \
    CERF_STR(CERF_VERSION_PATCH)

#define CERF_VERSION_WSTR \
    CERF_WSTR(CERF_VERSION_MAJOR) L"." \
    CERF_WSTR(CERF_VERSION_MINOR) L"." \
    CERF_WSTR(CERF_VERSION_PATCH)

// Full version string shown to users (window title, About box, file
// properties). Defaults to the clean semantic version; build.yml rewrites
// these two lines in CI to append the build's UTC timestamp + short commit
// SHA, e.g. "3.0.0 (2026-06-01 14:23 UTC, a1b2c3d)", so users comparing
// downloaded builds can tell which is fresher. The launcher (launcher.py)
// regex-parses CERF_VERSION_DISPLAY_STR from this file too.
#define CERF_VERSION_DISPLAY_STR   CERF_VERSION_STR
#define CERF_VERSION_DISPLAY_WSTR  CERF_VERSION_WSTR
