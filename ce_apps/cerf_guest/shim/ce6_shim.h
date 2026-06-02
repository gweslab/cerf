#pragma once

#define DDI 1

#include <windows.h>

typedef DWORD REG_TYPE;

#ifndef _BLENDFUNCTION_DEFINED
#define _BLENDFUNCTION_DEFINED
typedef struct _BLENDFUNCTION {
    BYTE BlendOp;
    BYTE BlendFlags;
    BYTE SourceConstantAlpha;
    BYTE AlphaFormat;
} BLENDFUNCTION, *PBLENDFUNCTION;
#endif

#ifndef AC_SRC_OVER
#define AC_SRC_OVER   0x00
#define AC_SRC_ALPHA  0x01
#endif

#ifdef __cplusplus
extern "C" {
#endif
void CerfDebugTx(const char* msg);
void CerfDebugTxX(const char* msg, DWORD value);
#ifdef __cplusplus
}
#endif

#if CERF_DEV_MODE
#define CERF_LOG(msg)        CerfDebugTx(msg)
#define CERF_LOG_X(msg, val) CerfDebugTxX((msg), (DWORD)(val))
#else
#define CERF_LOG(msg)        ((void)0)
#define CERF_LOG_X(msg, val) ((void)0)
#endif
