#ifndef CERF_NDIS_MINIPORT_H
#define CERF_NDIS_MINIPORT_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "cerf_ndis.h"

#define CERF_MP_FRAME_MAX 1500

BOOL CerfNdisInstall(void);
BOOL CerfMpRegistered(void);
BOOL CerfMpAdapterBound(void);
BOOL CerfMpNicChannelPresent(void);

const UCHAR* CerfMpMac(void);
ULONG CerfMpFilterGet(void);
void  CerfMpFilterSet(ULONG v);
ULONG CerfMpLookaheadGet(void);
void  CerfMpLookaheadSet(ULONG v);
ULONG CerfMpLinkUp(void);
ULONG CerfMpEthDbOff(void);
ULONG CerfMpOsMajor(void);

NDIS_STATUS CerfMpQueryInformation(NDIS_HANDLE adapter, ULONG oid, void* buf,
                                   UINT len, UINT* written, UINT* needed);
NDIS_STATUS CerfMpSetInformation(NDIS_HANDLE adapter, ULONG oid, void* buf,
                                 UINT len, UINT* read, UINT* needed);

#ifdef __cplusplus
}
#endif

#endif
