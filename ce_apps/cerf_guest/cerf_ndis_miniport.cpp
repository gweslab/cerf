#include "cerf_ndis.h"
#include "cerf_ndis_miniport.h"
#include "cerf_ndis_packet_rx.h"
#include "cerf_ndis_slot.h"
#include "cerf_debug_log.h"
#include "cerf_regs_map.h"

#include "cerfcore/peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "cerfcore/peripherals/cerf_virt/cerf_virt_nic_regs.h"

typedef struct {
    UCHAR  MajorNdisVersion;
    UCHAR  MinorNdisVersion;
    USHORT Filler;
    UINT   Reserved;
    PVOID  CheckForHangHandler;
    PVOID  DisableInterruptHandler;
    PVOID  EnableInterruptHandler;
    PVOID  HaltHandler;
    PVOID  HandleInterruptHandler;
    PVOID  InitializeHandler;
    PVOID  ISRHandler;
    PVOID  QueryInformationHandler;
    PVOID  ReconfigureHandler;
    PVOID  ResetHandler;
    PVOID  SendHandler;
    PVOID  SetInformationHandler;
    PVOID  TransferDataHandler;
    PVOID  ReturnPacketHandler;
    PVOID  SendPacketsHandler;
    PVOID  AllocateCompleteHandler;
} CerfMiniportChars40;

extern "C" BOOL CerfMpRegistered(void) {
    CerfMpSlot* mp = CerfMpFind();
    return mp && mp->wrapper != 0;
}

extern "C" BOOL CerfMpAdapterBound(void) {
    CerfMpSlot* mp = CerfMpSelf();
    BOOL        bound;
    if (!mp->life_cs_ready) return FALSE;
    EnterCriticalSection(&mp->life_cs);
    bound = mp->adapter != 0;
    LeaveCriticalSection(&mp->life_cs);
    return bound;
}

extern "C" const UCHAR* CerfMpMac(void) { return CerfMpSelf()->mac; }
extern "C" ULONG CerfMpFilterGet(void) { return CerfMpSelf()->filter; }
extern "C" void  CerfMpFilterSet(ULONG v) { CerfMpSelf()->filter = v; }
extern "C" ULONG CerfMpLookaheadGet(void) { return CerfMpSelf()->lookahead; }
extern "C" void  CerfMpLookaheadSet(ULONG v) { CerfMpSelf()->lookahead = v; }
extern "C" ULONG CerfMpLinkUp(void) {
    CerfMpSlot* mp = CerfMpFind();
    return mp && mp->nic && mp->nic[cerfcore::CerfVirt::kNicRegLinkUp / 4] ? 1u : 0u;
}

static volatile ULONG* CerfMpMapNic(CerfMpSlot* mp) {
    volatile ULONG* nic;

    if (mp->nic_page) return mp->nic_page;
    nic = (volatile ULONG*)CerfMapRegsPage(
        g_CerfVirtBase + cerfcore::CerfVirt::kNicRegsOffset, cerfcore::CerfVirt::kNicRegsSize);
    if (!nic) return 0;
    if (nic[cerfcore::CerfVirt::kNicRegMagic / 4] != cerfcore::CerfVirt::kNicMagic) {
        VirtualFree((LPVOID)nic, 0, MEM_RELEASE);
        return 0;
    }
    mp->nic_page = nic;
    return nic;
}

extern "C" BOOL CerfMpNicChannelPresent(void) {
    return CerfMpMapNic(CerfMpSelf()) != 0;
}

extern "C" ULONG CerfMpEthDbOff(void) { return CerfMpSelf()->ethdb_off; }
extern "C" ULONG CerfMpOsMajor(void)  { return CerfMpSelf()->os_major; }

static void CerfMpResolveLayout(CerfMpSlot* mp) {
    OSVERSIONINFOW ovi;

    if (mp->layout_resolved) return;
    mp->layout_resolved = 1;

    memset(&ovi, 0, sizeof(ovi));
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    if (!GetVersionExW(&ovi)) {
        CERF_LOG_X("ndis: GetVersionExW failed gle", GetLastError());
        return;
    }
    mp->os_major = ovi.dwMajorVersion;
    mp->os_minor = ovi.dwMinorVersion;

    if (mp->os_major == 2 && mp->os_minor < 11) {
        mp->ethdb_off = CERF_NDIS_MINIPORT_ETHDB_ALT;
        mp->block_off = CERF_NDIS_FILTER_BLOCK_CE2;
    } else if (mp->os_major <= 3) {
        mp->ethdb_off = CERF_NDIS_MINIPORT_ETHDB;
        mp->block_off = CERF_NDIS_FILTER_BLOCK_CE2;
    } else if (mp->os_major <= 6) {
        mp->ethdb_off = CERF_NDIS_MINIPORT_ETHDB;
        mp->block_off = CERF_NDIS_FILTER_BLOCK_CE5;
    } else {
        mp->ethdb_off = CERF_NDIS_MINIPORT_ETHDB;
        mp->block_off = CERF_NDIS_FILTER_BLOCK_CE7;
    }
    CERF_LOG_X("ndis: os major", mp->os_major);
    CERF_LOG_X("ndis: os minor", mp->os_minor);
    CERF_LOG_X("ndis: EthDB offset", mp->ethdb_off);
    CERF_LOG_X("ndis: filter block offset", mp->block_off);
}

static void* CerfMpFilter(CerfMpSlot* mp) {
    void* filter;

    if (!mp->adapter) return 0;
    CerfMpResolveLayout(mp);
    if (!mp->ethdb_off) return 0;

    filter = *(void**)((UCHAR*)mp->adapter + mp->ethdb_off);
    if (!filter) return 0;

    if (*(ULONG*)((UCHAR*)filter + mp->block_off) != (ULONG)mp->adapter) {
        CERF_LOG_X("ndis: Eth filter back-pointer mismatch at offset", mp->block_off);
        return 0;
    }
    return filter;
}

static ULONG CerfMpMaxFrame(void) {
    return cerfcore::CerfVirt::kNicSlotSize - cerfcore::CerfVirt::kNicSlotPayloadOff;
}

extern "C" NDIS_STATUS CerfMpSend(NDIS_HANDLE adapter, void* packet) {
    const CerfNdisApi* api = CerfNdisResolve();
    CerfMpSlot* mp = CerfMpSelf();
    ULONG  total, wseq, rseq, off;
    void*  buf;
    UCHAR* slot;

    if (adapter != mp->adapter)
        CERF_LOG_X("ndis: send arrived on a superseded adapter", (ULONG)adapter);
    if (!api || !mp->nic || !mp->stage || !packet) {
        CERF_LOG("ndis: send with no channel");
        return CERF_NDIS_STATUS_FAILURE;
    }

    if (!*((UCHAR*)packet + CERF_NDIS_PACKET_VALIDCOUNTS)) {
        void* b   = *(void**)((UCHAR*)packet + CERF_NDIS_PACKET_HEAD);
        ULONG sum = 0;
        ULONG cnt = 0;
        while (b) {
            sum += *(ULONG*)((UCHAR*)b + CERF_NDIS_BUFFER_BYTECOUNT);
            ++cnt;
            b = *(void**)((UCHAR*)b + CERF_NDIS_BUFFER_NEXT);
        }
        *(ULONG*)((UCHAR*)packet + CERF_NDIS_PACKET_COUNT)     = cnt;
        *(ULONG*)((UCHAR*)packet + CERF_NDIS_PACKET_TOTALLEN)  = sum;
        *(ULONG*)((UCHAR*)packet + CERF_NDIS_PACKET_PHYSCOUNT) = 0;
        *((UCHAR*)packet + CERF_NDIS_PACKET_VALIDCOUNTS)       = 1;
    }

    total = *(ULONG*)((UCHAR*)packet + CERF_NDIS_PACKET_TOTALLEN);
    buf   = *(void**)((UCHAR*)packet + CERF_NDIS_PACKET_HEAD);
    if (total == 0 || total > CerfMpMaxFrame()) {
        CERF_LOG_X("ndis: send rejected, total len", total);
        return CERF_NDIS_STATUS_FAILURE;
    }

    wseq = mp->nic[cerfcore::CerfVirt::kNicRegTxWriteSeq / 4];
    rseq = mp->nic[cerfcore::CerfVirt::kNicRegTxReadSeq / 4];
    if (wseq - rseq >= cerfcore::CerfVirt::kNicTxSlots) {
        CERF_LOG_X("ndis: send rejected, tx ring full at", wseq);
        return CERF_NDIS_STATUS_FAILURE;
    }

    slot = (UCHAR*)mp->stage + cerfcore::CerfVirt::kNicTxBufOffset +
           (wseq % cerfcore::CerfVirt::kNicTxSlots) * cerfcore::CerfVirt::kNicSlotSize;

    off = 0;
    while (buf && off < total) {
        void* va  = 0;
        UINT  n   = 0;
        api->QueryBuffer(buf, &va, &n);
        if (va && n) {
            if (off + n > total) n = total - off;
            memcpy(slot + cerfcore::CerfVirt::kNicSlotPayloadOff + off, va, n);
            off += n;
        }
        buf = *(void**)((UCHAR*)buf + CERF_NDIS_BUFFER_NEXT);
    }

    if (off != total) {
        CERF_LOG_X("ndis: send rejected, short buffer walk got", off);
        return CERF_NDIS_STATUS_FAILURE;
    }

    *(ULONG*)(slot + cerfcore::CerfVirt::kNicSlotLenOff) = off;
    mp->nic[cerfcore::CerfVirt::kNicRegTxWriteSeq / 4] = wseq + 1;
    return CERF_NDIS_STATUS_SUCCESS;
}

extern "C" NDIS_STATUS CerfMpTransferData(void* packet, UINT* transferred,
                                          NDIS_HANDLE adapter, NDIS_HANDLE ctx,
                                          UINT offset, UINT want) {
    const CerfNdisApi* api = CerfNdisResolve();
    CerfMpSlot* mp = CerfMpSelf();
    void* buf;
    UINT  done = 0;

    (void)adapter; (void)ctx;
    *transferred = 0;
    if (!api || !packet || !mp->rx_body) return CERF_NDIS_STATUS_FAILURE;
    if (offset > mp->rx_body_len) return CERF_NDIS_STATUS_FAILURE;
    if (offset + want > mp->rx_body_len) want = mp->rx_body_len - offset;

    buf = *(void**)((UCHAR*)packet + CERF_NDIS_PACKET_HEAD);
    while (buf && done < want) {
        void* va = 0;
        UINT  n  = 0;
        api->QueryBuffer(buf, &va, &n);
        if (va && n) {
            if (done + n > want) n = want - done;
            memcpy(va, mp->rx_body + offset + done, n);
            done += n;
        }
        buf = *(void**)((UCHAR*)buf + CERF_NDIS_BUFFER_NEXT);
    }
    *transferred = done;
    return CERF_NDIS_STATUS_SUCCESS;
}

static DWORD WINAPI CerfMpRxThread(LPVOID param) {
    const CerfNdisApi* api = CerfNdisResolve();
    CerfMpSlot* mp = (CerfMpSlot*)param;

    if (!api) return 0;

    CERF_LOG_X("ndis: rx thread start tid", GetCurrentThreadId());
    CERF_LOG_X("ndis: rx thread start consumed", mp->rx_consumed);

    while (!mp->rx_stop) {
        ULONG wseq  = mp->nic[cerfcore::CerfVirt::kNicRegRxWriteSeq / 4];
        ULONG ahead = (ULONG)(mp->rx_consumed - wseq);

        if (ahead != 0 && ahead < 0x80000000u) {
            CERF_LOG_X("ndis: rx consumer overshot wseq, consumed", mp->rx_consumed);
            CERF_LOG_X("ndis: rx consumer overshot wseq, wseq", wseq);
            CERF_LOG_X("ndis: rx consumer overshot, tid", GetCurrentThreadId());
            CERF_FATAL("ndis: rx ring consumer passed the producer");
        }

        while (mp->rx_consumed != wseq) {
            UCHAR* slot;
            ULONG  len;
            void*  filter;

            slot = (UCHAR*)mp->stage + cerfcore::CerfVirt::kNicRxBufOffset +
                   (mp->rx_consumed % cerfcore::CerfVirt::kNicRxSlots) *
                       cerfcore::CerfVirt::kNicSlotSize;
            len = *(ULONG*)(slot + cerfcore::CerfVirt::kNicSlotLenOff);

            filter = CerfMpFilter(mp);

            if (CerfNdisPacketRxReady() &&
                len >= CERF_MP_ETH_HDR && len <= CerfMpMaxFrame()) {
                if (CerfNdisPacketRxIndicate(slot + cerfcore::CerfVirt::kNicSlotPayloadOff,
                                             len)) {
                    ++mp->rx_consumed;
                    continue;
                }
                CERF_LOG_X("ndis: packet indicate failed, trying legacy, len", len);
            }

            if (filter && len >= CERF_MP_ETH_HDR && len <= CerfMpMaxFrame()) {
                memcpy(mp->rx_hdr, slot + cerfcore::CerfVirt::kNicSlotPayloadOff,
                       CERF_MP_ETH_HDR);
                mp->rx_body     = slot + cerfcore::CerfVirt::kNicSlotPayloadOff + CERF_MP_ETH_HDR;
                mp->rx_body_len = len - CERF_MP_ETH_HDR;

                void* lock = 0;
                if (mp->block_off == CERF_NDIS_FILTER_BLOCK_CE2 &&
                    api->AcquireSpinLock && api->ReleaseSpinLock) {
                    ULONG block = *(ULONG*)((UCHAR*)filter + mp->block_off);
                    lock = (void*)(block + CERF_NDIS_BLOCK_SPINLOCK_CE2);
                    api->AcquireSpinLock(lock);
                }

                api->EthIndicateReceive(filter, (NDIS_HANDLE)&mp->rx_body,
                                        (char*)mp->rx_hdr, mp->rx_hdr,
                                        CERF_MP_ETH_HDR, mp->rx_body,
                                        mp->rx_body_len, mp->rx_body_len);
                api->EthIndicateReceiveComplete(filter);

                if (lock) api->ReleaseSpinLock(lock);
                mp->rx_body = 0;
            } else {
                CERF_LOG_X("ndis: rx frame dropped, no consumer, len", len);
            }
            ++mp->rx_consumed;
        }
        mp->nic[cerfcore::CerfVirt::kNicRegRxReadSeq / 4] = mp->rx_consumed;
        Sleep(5);
    }
    return 0;
}

extern "C" NDIS_STATUS CerfMpInitialize(NDIS_STATUS* open_status, UINT* medium_index,
                                        ULONG* medium_array, UINT medium_count,
                                        NDIS_HANDLE adapter, NDIS_HANDLE config) {
    const CerfNdisApi* api = CerfNdisResolve();
    CerfMpSlot* mp = CerfMpSelf();
    UINT i;
    ULONG w0, w1;

    (void)config;
    CERF_LOG_X("ndis: initialize pid", mp->pid);
    CERF_LOG_X("ndis: initialize adapter", (ULONG)adapter);
    CERF_LOG_X("ndis: initialize prior rx thread", (ULONG)mp->rx_thread);
    *open_status = CERF_NDIS_STATUS_SUCCESS;
    if (!api) {
        CERF_LOG("ndis: initialize with no ndis api");
        return CERF_NDIS_STATUS_FAILURE;
    }

    for (i = 0; i < medium_count; ++i)
        if (medium_array[i] == CERF_NDIS_MEDIUM_802_3) break;
    if (i == medium_count) {
        *open_status = CERF_NDIS_STATUS_UNSUPPORTED_MEDIA;
        return CERF_NDIS_STATUS_UNSUPPORTED_MEDIA;
    }
    *medium_index = i;

    mp->nic = CerfMpMapNic(mp);
    if (!mp->nic) {
        CERF_LOG("ndis: cerf_virt NIC channel absent");
        return CERF_NDIS_STATUS_FAILURE;
    }
    if (!mp->stage) {
        mp->stage = (volatile UCHAR*)CerfMapRegsPage(
            g_CerfVirtBase + cerfcore::CerfVirt::kNicStageOffset,
            cerfcore::CerfVirt::kNicStageSize);
    }
    if (!mp->stage) return CERF_NDIS_STATUS_FAILURE;

    w0 = mp->nic[cerfcore::CerfVirt::kNicRegMacWord0 / 4];
    w1 = mp->nic[cerfcore::CerfVirt::kNicRegMacWord1 / 4];
    mp->mac[0] = (UCHAR)(w0);       mp->mac[1] = (UCHAR)(w0 >> 8);
    mp->mac[2] = (UCHAR)(w0 >> 16); mp->mac[3] = (UCHAR)(w0 >> 24);
    mp->mac[4] = (UCHAR)(w1);       mp->mac[5] = (UCHAR)(w1 >> 8);

    EnterCriticalSection(&mp->life_cs);

    if (mp->rx_thread) {
        CERF_LOG_X("ndis: initialize stopping previous rx thread",
                   (ULONG)mp->rx_thread);
        mp->rx_stop = 1;
        if (WaitForSingleObject(mp->rx_thread, 2000) != WAIT_OBJECT_0)
            CERF_FATAL("ndis: previous rx thread did not exit");
        CloseHandle(mp->rx_thread);
        mp->rx_thread = 0;
    }

    mp->adapter     = adapter;
    mp->lookahead   = CERF_MP_FRAME_MAX;
    mp->rx_consumed = mp->nic[cerfcore::CerfVirt::kNicRegRxWriteSeq / 4];

    CerfMpResolveLayout(mp);

    api->MSetAttributesEx(adapter, adapter, 0, 0, 0);
    if (!CerfNdisPacketRxInit(adapter) && mp->os_major >= 7)
        CERF_LOG_X("ndis: packet receive unavailable, os major", mp->os_major);

    if (api->MIndicateStatus) {
        api->MIndicateStatus(adapter, CERF_NDIS_STATUS_MEDIA_CONNECT, 0, 0);
        if (api->MIndicateStatusComplete) api->MIndicateStatusComplete(adapter);
    }

    mp->rx_stop   = 0;
    mp->rx_thread = CreateThread(0, 0, CerfMpRxThread, mp, 0, 0);
    if (!mp->rx_thread) {
        CERF_LOG_X("ndis: rx thread create failed, adapter has no receiver, gle",
                   GetLastError());
        CerfNdisPacketRxShutdown();
        mp->adapter = 0;
        LeaveCriticalSection(&mp->life_cs);
        return CERF_NDIS_STATUS_FAILURE;
    }

    LeaveCriticalSection(&mp->life_cs);

    CERF_LOG_X("ndis: miniport initialized, medium index", i);
    return CERF_NDIS_STATUS_SUCCESS;
}

extern "C" void CerfMpHalt(NDIS_HANDLE adapter) {
    CerfMpSlot* mp = CerfMpSelf();
    DWORD wait;

    EnterCriticalSection(&mp->life_cs);

    if (mp->adapter != adapter) {
        CERF_LOG_X("ndis: halt of a superseded adapter, live one kept",
                   (ULONG)adapter);
        LeaveCriticalSection(&mp->life_cs);
        return;
    }
    mp->rx_stop = 1;
    if (mp->rx_thread) {
        CERF_LOG_X("ndis: halt joining rx thread", (ULONG)mp->rx_thread);
        wait = WaitForSingleObject(mp->rx_thread, 2000);
        if (wait != WAIT_OBJECT_0) {
            CERF_LOG_X("ndis: halt rx thread wait result", wait);
            CERF_FATAL("ndis: rx thread did not exit on halt");
        }
        CloseHandle(mp->rx_thread);
        mp->rx_thread = 0;
    }
    mp->adapter = 0;
    if (!CerfNdisPacketRxShutdown())
        CERF_LOG("ndis: halt left the packet pools unreclaimed");
    LeaveCriticalSection(&mp->life_cs);
    CERF_LOG("ndis: miniport halted");
}

extern "C" NDIS_STATUS CerfMpReset(BOOLEAN* addressing_reset, NDIS_HANDLE adapter) {
    (void)adapter;
    *addressing_reset = FALSE;
    return CERF_NDIS_STATUS_SUCCESS;
}

extern "C" void CerfMpNoOp(NDIS_HANDLE adapter) { (void)adapter; }

extern "C" void CerfMpReturnPacket(NDIS_HANDLE adapter, void* packet) {
    (void)adapter;
    CerfNdisPacketRxReturn(packet);
}

extern "C" NDIS_STATUS DriverEntry(void* driver_object, void* registry_path) {
    const CerfNdisApi* api = CerfNdisResolve();
    CerfMpSlot* mp;
    static CerfMiniportChars40 chars;
    NDIS_HANDLE wrapper = 0;
    NDIS_STATUS st;

    CERF_LOG_INIT(CERF_LOG_CH_SHARED_FOLDERS);
    mp = CerfMpSelf();
    if (!mp->life_cs_ready) {
        InitializeCriticalSection(&mp->life_cs);
        mp->life_cs_ready = TRUE;
    }
    CERF_LOG_X("ndis: DriverEntry pid", mp->pid);
    CERF_LOG_X("ndis: DriverEntry prior wrapper", (ULONG)mp->wrapper);
    if (!api) return CERF_NDIS_STATUS_FAILURE;

    memset(&chars, 0, sizeof(chars));
    chars.MajorNdisVersion        = 4;
    chars.MinorNdisVersion        = 0;
    chars.DisableInterruptHandler = (PVOID)CerfMpNoOp;
    chars.EnableInterruptHandler  = (PVOID)CerfMpNoOp;
    chars.HaltHandler             = (PVOID)CerfMpHalt;
    chars.HandleInterruptHandler  = (PVOID)CerfMpNoOp;
    chars.InitializeHandler       = (PVOID)CerfMpInitialize;
    chars.ISRHandler              = 0;
    chars.QueryInformationHandler = (PVOID)CerfMpQueryInformation;
    chars.ResetHandler            = (PVOID)CerfMpReset;
    chars.SendHandler             = (PVOID)CerfMpSend;
    chars.SetInformationHandler   = (PVOID)CerfMpSetInformation;
    chars.TransferDataHandler     = (PVOID)CerfMpTransferData;
    chars.ReturnPacketHandler     = (PVOID)CerfMpReturnPacket;

    api->InitializeWrapper(&wrapper, driver_object, registry_path, 0);
    st = api->MRegisterMiniport(wrapper, &chars, sizeof(chars));
    if (st != CERF_NDIS_STATUS_SUCCESS) {
        CERF_LOG_X("ndis: NdisMRegisterMiniport failed", (ULONG)st);
        api->TerminateWrapper(wrapper, 0);
        return st;
    }
    mp->wrapper = wrapper;
    CERF_LOG("ndis: miniport registered");
    return CERF_NDIS_STATUS_SUCCESS;
}
