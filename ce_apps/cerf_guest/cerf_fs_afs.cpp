#include "cerf_fs_driver.h"
#include "cerf_regs_map.h"

#include <windows.h>
#include <pkfuncs.h>

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

#define AFS_VERSION    0x00000004
#define HT_FILE        7
#define HT_FIND        8
#define HT_AFSVOLUME   16
#define OID_FIRST_AFS  0

#undef SetHandleOwner
extern "C" {
BOOL SetHandleOwner(HANDLE h, HANDLE hProc);
int  RegisterAFSName(LPCWSTR pName);
BOOL DeregisterAFS(int index);
BOOL DeregisterAFSName(int index);
}

typedef BOOL (*PFN_RegisterAFS)(int, HANDLE, DWORD, DWORD);
typedef BOOL (*PFN_RegisterAFSEx)(int, HANDLE, DWORD, DWORD, DWORD);

static BOOL CerfRegisterAFS(int iAFS, HANDLE hApi, DWORD ctx) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    PFN_RegisterAFSEx ex;
    PFN_RegisterAFS reg;
    if (!core) return FALSE;
    ex = (PFN_RegisterAFSEx)GetProcAddressW(core, L"RegisterAFSEx");
    if (ex) return ex(iAFS, hApi, ctx, AFS_VERSION, 0);
    reg = (PFN_RegisterAFS)GetProcAddressW(core, L"RegisterAFS");
    if (reg) return reg(iAFS, hApi, ctx, AFS_VERSION);
    return FALSE;
}

#define CERF_AFS_METHODS   24
#define CERF_FILE_METHODS  14
#define CERF_FIND_METHODS  3

HANDLE g_hCerfFileAPI = NULL;
HANDLE g_hCerfFindAPI = NULL;

static HANDLE          s_hAFSAPI = NULL;
static CerfVol         s_vol = { -1 };
static CerfFsServerPB* s_pb = NULL;
static unsigned char*  s_iobuf = NULL;
static CRITICAL_SECTION s_cs;
static BOOL            s_inited = FALSE;

CerfFsServerPB* CerfFsPb(void)    { return s_pb; }
unsigned char*  CerfFsIoBuf(void) { return s_iobuf; }
void CerfFsLock(void)   { EnterCriticalSection(&s_cs); }
void CerfFsUnlock(void) { LeaveCriticalSection(&s_cs); }

int CerfFsResultToBool(unsigned long result) {
    if (result == CERF_FS_OK) return 1;
    if (result == CERF_FS_E_DISK_FULL) result = ERROR_DISK_FULL;
    SetLastError(result);
    return 0;
}

static SHELLFILECHANGEFUNC_t s_notify = NULL;

BOOL CerfFsCloseVolume(CerfVol* vol)               { (void)vol; return TRUE; }

BOOL CerfFsCloseAllFiles(CerfVol* vol, HANDLE hProc) { (void)vol; (void)hProc; return TRUE; }
void CerfFsNotify(CerfVol* vol, DWORD dwFlags)     { (void)vol; (void)dwFlags; }
BOOL CerfFsRegisterFileSystemFunction(CerfVol* vol, SHELLFILECHANGEFUNC_t pfn) {
    (void)vol; s_notify = pfn; return TRUE;
}

static BOOL CerfFsAfsReserved10(CerfVol* vol) {
    (void)vol;
    return FALSE;
}
static BOOL CerfFsAfsOidGetInfo(CerfVol* vol, DWORD oid, void* pInfo) {
    (void)vol; (void)oid; (void)pInfo;
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

static BOOL CerfFsAfsNotSupported(CerfVol* vol) {
    (void)vol;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

static const PFNVOID g_afsMethods[CERF_AFS_METHODS] = {
    (PFNVOID)CerfFsCloseVolume,
    (PFNVOID)NULL,
    (PFNVOID)CerfFsCreateDirectoryW,
    (PFNVOID)CerfFsRemoveDirectoryW,
    (PFNVOID)CerfFsGetFileAttributesW,
    (PFNVOID)CerfFsSetFileAttributesW,
    (PFNVOID)CerfFsCreateFileW,
    (PFNVOID)CerfFsDeleteFileW,
    (PFNVOID)CerfFsMoveFileW,
    (PFNVOID)CerfFsFindFirstFileW,
    (PFNVOID)CerfFsAfsReserved10,
    (PFNVOID)CerfFsAfsOidGetInfo,
    (PFNVOID)CerfFsDeleteAndRenameFileW,
    (PFNVOID)CerfFsCloseAllFiles,
    (PFNVOID)CerfFsGetDiskFreeSpaceW,
    (PFNVOID)CerfFsNotify,
    (PFNVOID)CerfFsRegisterFileSystemFunction,
    (PFNVOID)CerfFsFindFirstChangeNotificationW,
    (PFNVOID)NULL,
    (PFNVOID)NULL,
    (PFNVOID)NULL,
    (PFNVOID)CerfFsAfsNotSupported,
    (PFNVOID)CerfFsAfsNotSupported,
    (PFNVOID)CerfFsAfsNotSupported,
};

static const PFNVOID g_fileMethods[CERF_FILE_METHODS] = {
    (PFNVOID)CerfFsCloseFile,
    (PFNVOID)NULL,
    (PFNVOID)CerfFsReadFile,
    (PFNVOID)CerfFsWriteFile,
    (PFNVOID)CerfFsGetFileSize,
    (PFNVOID)CerfFsSetFilePointer,
    (PFNVOID)CerfFsGetFileInformationByHandle,
    (PFNVOID)CerfFsFlushFileBuffers,
    (PFNVOID)CerfFsGetFileTime,
    (PFNVOID)CerfFsSetFileTime,
    (PFNVOID)CerfFsSetEndOfFile,
    (PFNVOID)CerfFsFileIoControl,
    (PFNVOID)CerfFsReadFileWithSeek,
    (PFNVOID)CerfFsWriteFileWithSeek,
};

static const PFNVOID g_findMethods[CERF_FIND_METHODS] = {
    (PFNVOID)CerfFsFindClose,
    (PFNVOID)NULL,
    (PFNVOID)CerfFsFindNextFileW,
};

static const DWORD g_afsSig32[CERF_AFS_METHODS] = {
    0x000, 0x000, 0x014, 0x004, 0x004, 0x004, 0x410, 0x004,
    0x014, 0x050, 0x000, 0x010, 0x014, 0x000, 0x554, 0x000, 0x000,
    0x010,
    0x000, 0x000, 0x000,
    0x5110,
    0x000, 0x000,
};
static const DWORD g_fileSig32[CERF_FILE_METHODS] = {
    0x000, 0x000, 0x144, 0x144, 0x004, 0x010, 0x004, 0x000,
    0x054, 0x054, 0x000, 0x5110, 0x144, 0x144,
};
static const DWORD g_findSig32[CERF_FIND_METHODS] = {
    0x000, 0x000, 0x004,
};

static const ULONGLONG g_afsSig64[CERF_AFS_METHODS] = {
    FNSIG1(DW),
    FNSIG1(DW),
    FNSIG5(DW, I_WSTR, I_WSTR, I_PTR, DW),
    FNSIG2(DW, I_WSTR),
    FNSIG2(DW, I_WSTR),
    FNSIG3(DW, I_WSTR, DW),
    FNSIG11(DW, DW, I_WSTR, DW, DW, PTR, DW, DW, DW, I_PTR, DW),
    FNSIG2(DW, I_WSTR),
    FNSIG3(DW, I_WSTR, I_WSTR),
    FNSIG5(DW, DW, I_WSTR, IO_PTR, DW),
    FNSIG0(),
    FNSIG0(),
    FNSIG3(DW, I_WSTR, I_WSTR),
    FNSIG2(DW, DW),
    FNSIG6(DW, I_WSTR, O_PDW, O_PDW, O_PDW, O_PDW),
    FNSIG2(DW, DW),
    FNSIG2(DW, DW),
    FNSIG5(DW, DW, I_WSTR, DW, DW),
    FNSIG0(),
    FNSIG0(),
    FNSIG0(),
    FNSIG9(DW, DW, DW, IO_PTR, DW, IO_PTR, DW, O_PDW, IO_PDW),
    FNSIG5(DW, I_WSTR, DW, I_PTR, DW),
    FNSIG6(DW, I_WSTR, DW, O_PTR, DW, O_PDW),
};

static const ULONGLONG g_fileSig64[CERF_FILE_METHODS] = {
    FNSIG1(DW),
    FNSIG0(),
    FNSIG5(DW, O_PTR, DW, O_PDW, IO_PDW),
    FNSIG5(DW, I_PTR, DW, O_PDW, IO_PDW),
    FNSIG2(DW, O_PDW),
    FNSIG4(DW, DW, IO_PDW, DW),
    FNSIG3(DW, O_PTR, DW),
    FNSIG1(DW),
    FNSIG4(DW, O_PI64, O_PI64, O_PI64),
    FNSIG4(DW, IO_PI64, IO_PI64, IO_PI64),
    FNSIG1(DW),
    FNSIG8(DW, DW, IO_PTR, DW, IO_PTR, DW, O_PDW, IO_PDW),
    FNSIG7(DW, O_PTR, DW, O_PDW, IO_PDW, DW, DW),
    FNSIG7(DW, I_PTR, DW, O_PDW, IO_PDW, DW, DW),
};
static const ULONGLONG g_findSig64[CERF_FIND_METHODS] = {
    FNSIG1(DW),
    FNSIG0(),
    FNSIG2(DW, PTR),
};

typedef HANDLE (*PFN_CreateAPISet)(char*, USHORT, const PFNVOID*, const ULONGLONG*);
typedef BOOL   (*PFN_RegisterDirectMethods)(HANDLE, const PFNVOID*);

static BOOL CerfCreateApiSets(void) {
    OSVERSIONINFO ovi;
    BOOL wide;
    USHORT afsCount;
    HMODULE core = LoadLibraryW(L"coredll.dll");
    PFN_CreateAPISet pCreateAPISet =
        core ? (PFN_CreateAPISet)GetProcAddressW(core, L"CreateAPISet") : NULL;
    if (!pCreateAPISet) {
        CERF_LOG("cerf_guest: foldershare CreateAPISet unresolved");
        return FALSE;
    }

    ovi.dwOSVersionInfoSize = sizeof(ovi);
    GetVersionEx(&ovi);
    wide = (ovi.dwMajorVersion >= 6);

    afsCount = (ovi.dwMajorVersion == 5) ? 22 : 17;

    if (wide) {
        s_hAFSAPI     = pCreateAPISet("CFSV", afsCount,          g_afsMethods,  g_afsSig64);
        g_hCerfFileAPI = pCreateAPISet("CFSF", CERF_FILE_METHODS, g_fileMethods, g_fileSig64);
        g_hCerfFindAPI = pCreateAPISet("CFSS", CERF_FIND_METHODS, g_findMethods, g_findSig64);
    } else {
        s_hAFSAPI     = pCreateAPISet("CFSV", afsCount,          g_afsMethods,  (const ULONGLONG*)g_afsSig32);
        g_hCerfFileAPI = pCreateAPISet("CFSF", CERF_FILE_METHODS, g_fileMethods, (const ULONGLONG*)g_fileSig32);
        g_hCerfFindAPI = pCreateAPISet("CFSS", CERF_FIND_METHODS, g_findMethods, (const ULONGLONG*)g_findSig32);
    }
    if (!s_hAFSAPI || !g_hCerfFileAPI || !g_hCerfFindAPI) {
        CERF_LOG("cerf_guest: foldershare CreateAPISet FAILED");
        return FALSE;
    }
    CERF_LOG_X("cerf_guest: CFSV(AFS) apiset handle", (DWORD)s_hAFSAPI);
    CERF_LOG_X("cerf_guest: CFSF(file) apiset handle", (DWORD)g_hCerfFileAPI);
    CERF_LOG_X("cerf_guest: CFSS(find) apiset handle", (DWORD)g_hCerfFindAPI);

    CERF_LOG_X("cerf_guest: RegisterAPISet HT_FILE ok",
               RegisterAPISet(g_hCerfFileAPI, HT_FILE | REGISTER_APISET_TYPE));
    CERF_LOG_X("cerf_guest: RegisterAPISet HT_FIND ok",
               RegisterAPISet(g_hCerfFindAPI, HT_FIND | REGISTER_APISET_TYPE));

    if (ovi.dwMajorVersion >= 6) {
        PFN_RegisterDirectMethods pRDM =
            (PFN_RegisterDirectMethods)GetProcAddressW(core, L"RegisterDirectMethods");
        if (pRDM) {
            CERF_LOG_X("cerf_guest: RegisterAPISet HT_AFSVOLUME ok",
                       RegisterAPISet(s_hAFSAPI, HT_AFSVOLUME | REGISTER_APISET_TYPE));
            CERF_LOG_X("cerf_guest: RegisterDirectMethods AFS ok",  pRDM(s_hAFSAPI, g_afsMethods));
            CERF_LOG_X("cerf_guest: RegisterDirectMethods file ok", pRDM(g_hCerfFileAPI, g_fileMethods));
        }
    }
    return TRUE;
}

HANDLE CerfFsMakeHandle(HANDLE apiSet, void* ctx, HANDLE hProc) {
    HANDLE h = CreateAPIHandle(apiSet, ctx);
    if (!h) return INVALID_HANDLE_VALUE;
    if (hProc == NULL) {
        hProc = GetCurrentProcess();
        if (hProc) SetHandleOwner(h, hProc);
    }
    return h;
}

static void CerfReadMountName(volatile CerfFsChannel* ch, WCHAR* out, int cap) {
    int i;
    for (i = 0; i < cap - 1; ++i) {
        WCHAR c = (WCHAR)ch->MountPoint[i];
        if (!c) break;
        out[i] = c;
    }
    out[i] = 0;
}

static BOOL CerfBindSlot(int iAFS) {
    if (!CerfRegisterAFS(iAFS, s_hAFSAPI, (DWORD)&s_vol)) return FALSE;
    s_vol.iAFS = iAFS;
    CERF_LOG_X("cerf_guest: foldershare mounted iAFS", iAFS);
    return TRUE;
}

static void CerfMount(volatile CerfFsChannel* ch) {
    WCHAR base[64], cand[66];
    const WCHAR* n;
    int blen, iAFS, suffix;
    if (s_vol.iAFS != -1) return;
    CerfReadMountName(ch, base, 64);
    n = base;
    if (*n == L'\\' || *n == L'/') ++n;
    if (!*n) return;

    iAFS = RegisterAFSName(n);
    if (iAFS != -1 && GetLastError() == 0) {
        if (CerfBindSlot(iAFS)) return;
        DeregisterAFSName(iAFS);
        return;
    }
    if (CerfBindSlot(OID_FIRST_AFS)) return;

    blen = lstrlenW(n);
    if (blen > 64) blen = 64;
    memcpy(cand, n, blen * sizeof(WCHAR));
    for (suffix = 2; suffix <= 9; ++suffix) {
        cand[blen] = (WCHAR)(L'0' + suffix);
        cand[blen + 1] = 0;
        iAFS = RegisterAFSName(cand);
        if (iAFS != -1 && GetLastError() == 0) {
            if (CerfBindSlot(iAFS)) return;
            DeregisterAFSName(iAFS);
        }
    }
    CERF_LOG("cerf_guest: foldershare mount FAILED (no free AFS name)");
}

static void CerfUnmount(void) {
    if (s_vol.iAFS == -1) return;
    DeregisterAFS(s_vol.iAFS);
    if (s_vol.iAFS > OID_FIRST_AFS)
        DeregisterAFSName(s_vol.iAFS);
    CERF_LOG_X("cerf_guest: foldershare unmounted iAFS", s_vol.iAFS);
    s_vol.iAFS = -1;
}

static DWORD WINAPI CerfFsMountThread(LPVOID unused) {
    volatile CerfFsChannel* ch = CerfFsMapChannel();
    DWORD last_gen = 0xFFFFFFFFu;
    (void)unused;
    if (!ch) {
        CERF_LOG("cerf_guest: foldershare mount-thread no channel");
        return 0;
    }
    CERF_LOG("cerf_guest: foldershare mount-thread running");
    for (;;) {
        DWORD gen = ch->Generation;
        if (gen != last_gen) {
            last_gen = gen;

            CerfUnmount();
            if (ch->Enabled) CerfMount(ch);
        }
        Sleep(1000);
    }
}

void CerfFsAfsInit(void) {
    HANDLE t;
    if (s_inited) return;
    s_inited = TRUE;

    InitializeCriticalSection(&s_cs);
    {
        unsigned char* base = (unsigned char*)CerfMapRegsPage(
            g_CerfVirtBase + CerfVirt::kFsStageOffset, CerfVirt::kFsStageSize);
        if (!base) {
            CERF_LOG("cerf_guest: foldershare stage map FAILED");
            return;
        }
        s_pb    = (CerfFsServerPB*)(base + CerfVirt::kFsStagePbOff);
        s_iobuf = base + CerfVirt::kFsStageIoOff;
    }
    memset(s_pb, 0, sizeof(*s_pb));
    s_pb->fStructureSize = sizeof(*s_pb);

    if (!CerfCreateApiSets()) return;
    CerfFsNotifyInit();

    t = CreateThread(NULL, 0, CerfFsMountThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
    CERF_LOG("cerf_guest: foldershare AFS init complete");
}

static DWORD WINAPI CerfFsDirectThread(LPVOID unused) {
    (void)unused;
    CerfFsAfsInit();
    return 0;
}

void CerfStartFolderShareDirect(void) {
    static BOOL started = FALSE;
    HANDLE t;
    if (started) return;
    started = TRUE;
    t = CreateThread(NULL, 0, CerfFsDirectThread, NULL, 0, NULL);
    if (t) CloseHandle(t);
}
