#ifndef CERF_NDIS_H
#define CERF_NDIS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int          NDIS_STATUS;
typedef void*        NDIS_HANDLE;

#define CERF_NDIS_STATUS_SUCCESS            0x00000000
#define CERF_NDIS_STATUS_FAILURE            ((NDIS_STATUS)0xC0000001)
#define CERF_NDIS_STATUS_NOT_SUPPORTED      ((NDIS_STATUS)0xC0010017)
#define CERF_NDIS_STATUS_INVALID_LENGTH     ((NDIS_STATUS)0xC0010014)
#define CERF_NDIS_STATUS_UNSUPPORTED_MEDIA  ((NDIS_STATUS)0xC0010019)

#define CERF_NDIS_MEDIUM_802_3              0

#define CERF_NDIS_STATUS_MEDIA_CONNECT      ((NDIS_STATUS)0x4001000B)
#define CERF_NDIS_STATUS_MEDIA_DISCONNECT   ((NDIS_STATUS)0x4001000C)

typedef void        (*PFN_NdisInitializeWrapper)(NDIS_HANDLE*, void*, void*, void*);
typedef void        (*PFN_NdisTerminateWrapper)(NDIS_HANDLE, void*);
typedef NDIS_STATUS (*PFN_NdisMRegisterMiniport)(NDIS_HANDLE, void*, UINT);
typedef void        (*PFN_NdisMSetAttributesEx)(NDIS_HANDLE, NDIS_HANDLE, UINT, ULONG, ULONG);
typedef void        (*PFN_NdisMIndicateStatus)(NDIS_HANDLE, NDIS_STATUS, void*, UINT);
typedef void        (*PFN_NdisMIndicateStatusComplete)(NDIS_HANDLE);
typedef void        (*PFN_EthFilterDprIndicateReceive)(void*, NDIS_HANDLE, char*, void*,
                                                       UINT, void*, UINT, UINT);
typedef void        (*PFN_EthFilterDprIndicateReceiveComplete)(void*);
typedef void        (*PFN_NdisQueryBuffer)(void*, void**, UINT*);
typedef ULONG       (*PFN_NdisRegisterAdapter)(NDIS_STATUS*, void*, void*);
typedef DWORD       (*PFN_NDS_Init)(const wchar_t*);
typedef void        (*PFN_NdisAllocatePacketPool)(NDIS_STATUS*, void**, UINT, UINT);
typedef void        (*PFN_NdisAllocatePacket)(NDIS_STATUS*, void**, void*);
typedef void        (*PFN_NdisAllocateBufferPool)(NDIS_STATUS*, void**, UINT);
typedef void        (*PFN_NdisAllocateBuffer)(NDIS_STATUS*, void**, void*, void*, UINT);
typedef void        (*PFN_NdisFreeBuffer)(void*);
typedef void        (*PFN_NdisFreePacket)(void*);
typedef void        (*PFN_NdisFreePool)(void*);
typedef void        (*PFN_NdisSpinLock)(void*);
typedef void        (*PFN_NdisQueryPacket)(void*, UINT*, UINT*, void**, UINT*);

typedef struct {
    HMODULE                                 hndis;
    PFN_NdisInitializeWrapper               InitializeWrapper;
    PFN_NdisTerminateWrapper                TerminateWrapper;
    PFN_NdisMRegisterMiniport               MRegisterMiniport;
    PFN_NdisMSetAttributesEx                MSetAttributesEx;
    PFN_NdisMIndicateStatus                 MIndicateStatus;
    PFN_NdisMIndicateStatusComplete         MIndicateStatusComplete;
    PFN_EthFilterDprIndicateReceive         EthIndicateReceive;
    PFN_EthFilterDprIndicateReceiveComplete EthIndicateReceiveComplete;
    PFN_NdisQueryBuffer                     QueryBuffer;
    PFN_NdisRegisterAdapter                 RegisterAdapter;
    PFN_NDS_Init                            NdsInit;
    PFN_NdisAllocatePacketPool              AllocatePacketPool;
    PFN_NdisAllocatePacket                  AllocatePacket;
    PFN_NdisAllocateBufferPool              AllocateBufferPool;
    PFN_NdisAllocateBuffer                  AllocateBuffer;
    PFN_NdisFreeBuffer                      FreeBuffer;
    PFN_NdisFreePacket                      FreePacket;
    PFN_NdisFreePool                        FreePacketPool;
    PFN_NdisFreePool                        FreeBufferPool;
    PFN_NdisSpinLock                        AcquireSpinLock;
    PFN_NdisSpinLock                        ReleaseSpinLock;
    PFN_NdisQueryPacket                     QueryPacket;
} CerfNdisApi;

#define CERF_NDIS_FILTER_BLOCK_CE2    76
#define CERF_NDIS_FILTER_BLOCK_CE5    24
#define CERF_NDIS_FILTER_BLOCK_CE7    164
#define CERF_NDIS_BLOCK_SPINLOCK_CE2  60

#define CERF_NDIS_MINIPORT_ETHDB      248
#define CERF_NDIS_MINIPORT_ETHDB_ALT  256

#define CERF_NDIS_PACKET_PHYSCOUNT    0
#define CERF_NDIS_PACKET_TOTALLEN     4
#define CERF_NDIS_PACKET_HEAD         8
#define CERF_NDIS_PACKET_COUNT        20
#define CERF_NDIS_PACKET_VALIDCOUNTS  28
#define CERF_NDIS_PACKET_OOB_OFF      30
#define CERF_NDIS_OOB_STATUS          28

#define CERF_NDIS_BLOCK_PKTINDICATE_FROM_ETHDB  16

#define CERF_NDIS_BUFFER_NEXT         0
#define CERF_NDIS_BUFFER_BYTECOUNT    8

const CerfNdisApi* CerfNdisResolve(void);

#ifdef __cplusplus
}
#endif

#endif
