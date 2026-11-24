#include <windows.h>

#include "cerf_regs_map.h"
#include "cerf_debug_log.h"

#include "cerfcore/peripherals/cerf_virt/cerf_virt_addr_map.h"

#define CERF_ORDINAL_FLAG   0x80000000u

typedef BOOL  (APIENTRY *PFN_DrvEnableDriver)(ULONG, ULONG, void*, void*);
typedef BOOL  (APIENTRY *PFN_HALInit)(void*, BOOL, DWORD);
typedef BOOL  (APIENTRY *PFN_DllEntry)(HANDLE, DWORD, LPVOID);
typedef void  (*PFN_SetCarrierName)(const wchar_t*);
typedef DWORD (*PFN_CddInit)(DWORD);
typedef BOOL  (*PFN_CddDeinit)(DWORD);
typedef DWORD (*PFN_CddOpen)(DWORD, DWORD, DWORD);
typedef BOOL  (*PFN_CddClose)(DWORD);
typedef DWORD (*PFN_CddRead)(DWORD, LPVOID, DWORD);
typedef DWORD (*PFN_CddWrite)(DWORD, LPCVOID, DWORD);
typedef int   (*PFN_DriverEntry)(void*, void*);
typedef DWORD (*PFN_CddSeek)(DWORD, LONG, WORD);
typedef BOOL  (*PFN_CddIOControl)(DWORD, DWORD, PBYTE, DWORD, PBYTE, DWORD, PDWORD);
typedef int   (*PFN_FlipDisplay)(DWORD);
typedef int   (*PFN_ScreenUpdate)(DWORD, const DWORD*);
typedef DWORD (*PFN_ClaimFreeBuffer)(DWORD);
typedef int   (*PFN_SetSurfaceModified)(void*);

#define CERF_STUB_MAX_PROC 8

typedef struct { DWORD pid; HMODULE hinst; } CerfStubInst;
static CerfStubInst s_inst[CERF_STUB_MAX_PROC];
static LONG         s_inst_next = 0;

static void CerfStubSetInst(HMODULE h) {
    DWORD pid = GetCurrentProcessId();
    LONG  idx;
    int   i;
    for (i = 0; i < CERF_STUB_MAX_PROC; ++i)
        if (s_inst[i].pid == pid) return;
    idx = InterlockedIncrement(&s_inst_next) - 1;
    if (idx < 0 || idx >= CERF_STUB_MAX_PROC) return;
    s_inst[idx].hinst = h;
    s_inst[idx].pid   = pid;
}

static HMODULE CerfStubInstOf(void) {
    DWORD pid = GetCurrentProcessId();
    int   i;
    for (i = 0; i < CERF_STUB_MAX_PROC; ++i)
        if (s_inst[i].pid == pid) return s_inst[i].hinst;
    return NULL;
}

/* CE3 ROMs have no DLL-RW reservation (ROMHDR.dllfirst<<16 == 0), so the
   injected module's writable statics are one physical instance shared across
   all loading processes. A body base is a VirtualAlloc VA valid only in its
   creator - so map state is keyed by pid; gwes and device.exe map their own. */
typedef struct {
    DWORD               pid;
    void*               body_base;
    PFN_DrvEnableDriver drv;
    PFN_HALInit         halinit;
    PFN_DriverEntry     driver_entry;
    PFN_CddInit         cdd_init;
    PFN_CddDeinit       cdd_deinit;
    PFN_CddOpen         cdd_open;
    PFN_CddClose        cdd_close;
    PFN_CddRead         cdd_read;
    PFN_CddWrite        cdd_write;
    PFN_CddSeek         cdd_seek;
    PFN_CddIOControl    cdd_ioctl;
    PFN_FlipDisplay        init_flipping;
    PFN_FlipDisplay        term_flipping;
    PFN_ScreenUpdate       screen_update;
    PFN_ClaimFreeBuffer    claim_free_buffer;
    PFN_SetSurfaceModified set_surface_modified;
} CerfStubSlot;
static CerfStubSlot s_slot[CERF_STUB_MAX_PROC];
static LONG         s_slot_next = 0;

static CerfStubSlot* CerfStubCurSlot(void) {
    DWORD pid = GetCurrentProcessId();
    int i;
    for (i = 0; i < CERF_STUB_MAX_PROC; ++i)
        if (s_slot[i].pid == pid) return &s_slot[i];
    return NULL;
}

static void CerfCopy(void* dst, const void* src, ULONG n) {
    UCHAR* d = (UCHAR*)dst;
    const UCHAR* s = (const UCHAR*)src;
    while (n--) *d++ = *s++;
}

static void* CerfMapBody(const UCHAR* img) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)img;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { CERF_LOG("map: bad MZ"); return NULL; }
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { CERF_LOG("map: bad PE"); return NULL; }
    const IMAGE_OPTIONAL_HEADER* opt = &nt->OptionalHeader;

    UCHAR* base = (UCHAR*)VirtualAlloc(NULL, opt->SizeOfImage,
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_EXECUTE_READWRITE);
    if (!base) { CERF_LOG_X("map: VirtualAlloc FAILED gle", GetLastError()); return NULL; }
    CERF_LOG_X("map: image base", (DWORD)base);
    CERF_LOG_X("map: mapping pid", GetCurrentProcessId());

    CerfCopy(base, img, opt->SizeOfHeaders);

    const IMAGE_SECTION_HEADER* sec = (const IMAGE_SECTION_HEADER*)
        ((const UCHAR*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        ULONG vsz  = sec[i].Misc.VirtualSize;
        ULONG rsz  = sec[i].SizeOfRawData;
        ULONG copy = (rsz < vsz) ? rsz : vsz;   /* VirtualAlloc zero-fills the bss tail */
        if (copy && sec[i].PointerToRawData)
            CerfCopy(base + sec[i].VirtualAddress, img + sec[i].PointerToRawData, copy);
    }

    LONG delta = (LONG)((ULONG)base - opt->ImageBase);
    if (delta) {
        const IMAGE_DATA_DIRECTORY* rd =
            &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        const IMAGE_BASE_RELOCATION* rb =
            (const IMAGE_BASE_RELOCATION*)(base + rd->VirtualAddress);
        ULONG done = 0;
#if defined(MIPS)
        USHORT* pHi = NULL;
        BOOL    matchedHi = FALSE;
#endif
        while (done < rd->Size && rb->SizeOfBlock) {
            ULONG cnt = (rb->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            const USHORT* ent = (const USHORT*)((const UCHAR*)rb + sizeof(IMAGE_BASE_RELOCATION));
            for (ULONG j = 0; j < cnt; ++j) {
                USHORT type = (USHORT)(ent[j] >> 12);
                USHORT off  = (USHORT)(ent[j] & 0x0FFF);
                UCHAR* fa   = base + rb->VirtualAddress + off;
                if (type == IMAGE_REL_BASED_HIGHLOW)
                    *(ULONG*)fa += (ULONG)delta;
                else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                }
#if defined(MIPS)
                else if (type == IMAGE_REL_BASED_HIGH) {
                    pHi = (USHORT*)fa; matchedHi = TRUE;
                }
                else if (type == IMAGE_REL_BASED_LOW) {
                    USHORT* pLo = (USHORT*)fa;
                    if (matchedHi) {
                        ULONG fv = ((ULONG)(*pHi) << 16) + *pLo + (ULONG)delta;
                        *pHi = (USHORT)((fv + 0x8000u) >> 16);
                        *pLo = (USHORT)(fv & 0xFFFFu);
                        matchedHi = FALSE;
                    } else {
                        ULONG fv = (ULONG)((LONG)(SHORT)*pLo + delta);
                        *pLo = (USHORT)(fv & 0xFFFFu);
                    }
                }
                else if (type == IMAGE_REL_BASED_HIGHADJ) {
                    USHORT* pHiA = (USHORT*)fa;
                    SHORT lowRaw = (j + 1 < cnt) ? (SHORT)ent[j + 1] : (SHORT)0;
                    *pHiA = (USHORT)(*pHiA +
                        (USHORT)(((LONG)lowRaw + delta + 0x8000) >> 16));
                    ++j;
                }
                else if (type == IMAGE_REL_BASED_MIPS_JMPADDR) {
                    ULONG* pI = (ULONG*)fa;
                    ULONG fv = (*pI & 0x03FFFFFFu) + (ULONG)(delta >> 2);
                    *pI = (*pI & 0xFC000000u) | (fv & 0x03FFFFFFu);
                }
#endif
                else {
                    CERF_LOG_X("map: unhandled reloc type", type);
                    return NULL;
                }
            }
            done += rb->SizeOfBlock;
            rb = (const IMAGE_BASE_RELOCATION*)((const UCHAR*)rb + rb->SizeOfBlock);
        }
    }

    const IMAGE_DATA_DIRECTORY* id = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id->Size) {
        const IMAGE_IMPORT_DESCRIPTOR* imp =
            (const IMAGE_IMPORT_DESCRIPTOR*)(base + id->VirtualAddress);
        for (; imp->Name; ++imp) {
            const char* dll = (const char*)(base + imp->Name);
            wchar_t wdll[64];
            int k = 0;
            for (; dll[k] && k < 63; ++k) wdll[k] = (wchar_t)(UCHAR)dll[k];
            wdll[k] = 0;
            HMODULE h = LoadLibraryW(wdll);
            if (!h) { CERF_LOG_X("map: dep LoadLibrary FAILED gle", GetLastError()); return NULL; }

            ULONG thunkRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                     : imp->FirstThunk;
            ULONG* oft = (ULONG*)(base + thunkRva);
            ULONG* ft  = (ULONG*)(base + imp->FirstThunk);
            for (; *oft; ++oft, ++ft) {
                FARPROC fn;
                if (*oft & CERF_ORDINAL_FLAG) {
                    fn = GetProcAddressW(h, (LPCWSTR)(*oft & 0xFFFFu));
                } else {
                    const IMAGE_IMPORT_BY_NAME* ibn =
                        (const IMAGE_IMPORT_BY_NAME*)(base + *oft);
                    wchar_t wn[128];
                    int m = 0;
                    for (; ibn->Name[m] && m < 127; ++m) wn[m] = (wchar_t)(UCHAR)ibn->Name[m];
                    wn[m] = 0;
                    fn = GetProcAddressW(h, wn);
                }
                if (!fn) {
                    if (*oft & CERF_ORDINAL_FLAG) {
                        CERF_LOG_X("map: import resolve FAILED, coredll ordinal", *oft & 0xFFFFu);
                    } else {
                        const IMAGE_IMPORT_BY_NAME* ibn =
                            (const IMAGE_IMPORT_BY_NAME*)(base + *oft);
                        CERF_LOG("map: import resolve FAILED, by-name:");
                        CERF_LOG((const char*)ibn->Name);
                    }
                    return NULL;
                }
                *ft = (ULONG)fn;
            }
        }
    }

    FlushInstructionCache(GetCurrentProcess(), base, opt->SizeOfImage);

    if (opt->AddressOfEntryPoint) {
        PFN_DllEntry ep = (PFN_DllEntry)(base + opt->AddressOfEntryPoint);
        if (!ep((HANDLE)base, DLL_PROCESS_ATTACH, NULL)) {
            CERF_LOG("map: body DllMain returned FALSE");
            return NULL;
        }
    }
    return base;
}

static void* CerfFindExport(const UCHAR* base, const char* name) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY* ed =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed->Size) return NULL;
    const IMAGE_EXPORT_DIRECTORY* exp =
        (const IMAGE_EXPORT_DIRECTORY*)(base + ed->VirtualAddress);
    const ULONG*  names = (const ULONG*)(base + exp->AddressOfNames);
    const USHORT* ords  = (const USHORT*)(base + exp->AddressOfNameOrdinals);
    const ULONG*  funcs = (const ULONG*)(base + exp->AddressOfFunctions);
    for (ULONG i = 0; i < exp->NumberOfNames; ++i) {
        const char* en = (const char*)(base + names[i]);
        int k = 0;
        while (en[k] && name[k] && en[k] == name[k]) ++k;
        if (en[k] == 0 && name[k] == 0)
            return (void*)(base + funcs[ords[i]]);
    }
    return NULL;
}

/* Idempotent: gwes loads this stub as the display driver, device.exe loads the
   same stub as the CDD_* stream driver (driver-in-driver), and each maps the
   one body into its own process here. */
static BOOL CerfEnsureBody(void) {
    DWORD pid = GetCurrentProcessId();
    CerfStubSlot* slot = CerfStubCurSlot();
    const ULONG* hdr;
    const UCHAR* body;
    ULONG size, mapped;
    void* base;
    LONG idx;
    PFN_SetCarrierName set_name;

    if (slot && slot->body_base) return TRUE;

    hdr = (const ULONG*)CerfMapRegsPage(g_CerfVirtBase + cerfcore::CerfVirt::kGuestBodyOffset,
                                        cerfcore::CerfVirt::kGuestBodyHdrSize);
    if (!hdr) { CERF_LOG("stub: body header map FAILED"); return FALSE; }
    size = hdr[0];
    CERF_LOG_X("stub: body size", size);
    if (size == 0) {
        CERF_LOG("stub: body size 0 - host did not stage cerf_guest");
        return FALSE;
    }

    mapped = (size + 0xFFFu) & ~0xFFFu;
    body = (const UCHAR*)CerfMapRegsPage(g_CerfVirtBase + cerfcore::CerfVirt::kGuestBodyOffset +
                                             cerfcore::CerfVirt::kGuestBodyHdrSize,
                                         mapped);
    if (!body) { CERF_LOG("stub: body map FAILED"); return FALSE; }

    base = CerfMapBody(body);
    if (!base) { CERF_LOG("stub: manual map FAILED"); return FALSE; }

    idx = InterlockedIncrement(&s_slot_next) - 1;
    if (idx < 0 || idx >= CERF_STUB_MAX_PROC) {
        CERF_LOG("stub: out of per-process slots");
        return FALSE;
    }
    slot = &s_slot[idx];

    slot->drv           = (PFN_DrvEnableDriver)CerfFindExport((const UCHAR*)base, "DrvEnableDriver");
    slot->halinit       = (PFN_HALInit)     CerfFindExport((const UCHAR*)base, "HALInit");
    slot->driver_entry  = (PFN_DriverEntry) CerfFindExport((const UCHAR*)base, "DriverEntry");
    slot->cdd_init      = (PFN_CddInit)     CerfFindExport((const UCHAR*)base, "CDD_Init");
    slot->cdd_deinit    = (PFN_CddDeinit)   CerfFindExport((const UCHAR*)base, "CDD_Deinit");
    slot->cdd_open      = (PFN_CddOpen)     CerfFindExport((const UCHAR*)base, "CDD_Open");
    slot->cdd_close     = (PFN_CddClose)    CerfFindExport((const UCHAR*)base, "CDD_Close");
    slot->cdd_read      = (PFN_CddRead)     CerfFindExport((const UCHAR*)base, "CDD_Read");
    slot->cdd_write     = (PFN_CddWrite)    CerfFindExport((const UCHAR*)base, "CDD_Write");
    slot->cdd_seek      = (PFN_CddSeek)     CerfFindExport((const UCHAR*)base, "CDD_Seek");
    slot->cdd_ioctl     = (PFN_CddIOControl)CerfFindExport((const UCHAR*)base, "CDD_IOControl");
    slot->init_flipping = (PFN_FlipDisplay)CerfFindExport((const UCHAR*)base, "InitializeFlipping");
    slot->term_flipping = (PFN_FlipDisplay)CerfFindExport((const UCHAR*)base, "TerminateFlipping");
    slot->screen_update = (PFN_ScreenUpdate)CerfFindExport((const UCHAR*)base, "ScreenUpdateByFlipEx");
    slot->claim_free_buffer =
        (PFN_ClaimFreeBuffer)CerfFindExport((const UCHAR*)base, "ClaimFreeBuffer");
    slot->set_surface_modified =
        (PFN_SetSurfaceModified)CerfFindExport((const UCHAR*)base, "SetSurfaceModified");

    set_name = (PFN_SetCarrierName)CerfFindExport((const UCHAR*)base, "CerfSetCarrierName");
    if (set_name) {
        wchar_t self[MAX_PATH];
        HMODULE inst = CerfStubInstOf();
        if (!inst) {
            CERF_LOG_X("stub: no module handle for pid", pid);
        } else if (GetModuleFileNameW(inst, self, MAX_PATH) > 0) {
            set_name(self);
            CERF_LOG("stub: handed carrier name to body");
        }
    }

    slot->body_base = base;
    slot->pid = pid;   /* publish pid last: CerfStubCurSlot keys on it */
    return TRUE;
}

static CerfStubSlot* CerfStubLoadedBody(void) {
    if (!CerfEnsureBody()) CERF_FATAL("stub: body is not mapped in this process - halting");
    return CerfStubCurSlot();
}

extern "C" BOOL APIENTRY DrvEnableDriver(ULONG iEngineVersion, ULONG cj,
                                          void* pded, void* pCallbacks) {
    CERF_LOG_INIT(CERF_LOG_CH_STUB);
    CERF_LOG_X("stub: DrvEnableDriver iEngineVersion", iEngineVersion);
    if (!CerfEnsureBody()) {
        CERF_LOG("stub: body bring-up FAILED - display unavailable");
        return FALSE;
    }
    return CerfStubCurSlot()->drv(iEngineVersion, cj, pded, pCallbacks);
}

/* GetProcAddress resolves against the stub, not the manual-mapped body, so a
   by-name entry point unmirrored here returns NULL and the body's is unreachable
   (as DrvEnableDriver already is). HALInit = the DirectDraw HAL entry. */
extern "C" BOOL APIENTRY HALInit(void* lpddhi, BOOL bUnused, DWORD modeidx) {
    CERF_LOG_INIT(CERF_LOG_CH_STUB);
    CERF_LOG("stub: HALInit");
    if (!CerfEnsureBody()) {
        CERF_LOG("stub: HALInit body unavailable - DirectDraw HAL FALSE");
        return FALSE;
    }
    return CerfStubCurSlot()->halinit(lpddhi, bUnused, modeidx);
}

extern "C" int DriverEntry(void* driver_object, void* registry_path) {
    CERF_LOG_INIT(CERF_LOG_CH_STUB);
    CERF_LOG("stub: DriverEntry (NDIS miniport)");
    if (!CerfEnsureBody()) return (int)0xC0000001;
    return CerfStubCurSlot()->driver_entry(driver_object, registry_path);
}

extern "C" DWORD CDD_Init(DWORD dwContext) {
    CERF_LOG_INIT(CERF_LOG_CH_STUB);
    CERF_LOG("stub: CDD_Init (device.exe carrier)");
    if (!CerfEnsureBody()) return 0;
    return CerfStubCurSlot()->cdd_init(dwContext);
}
extern "C" BOOL  CDD_Deinit(DWORD d)                   { return CerfStubLoadedBody()->cdd_deinit(d); }
extern "C" DWORD CDD_Open(DWORD d, DWORD a, DWORD s)   { return CerfStubLoadedBody()->cdd_open(d, a, s); }
extern "C" BOOL  CDD_Close(DWORD h)                    { return CerfStubLoadedBody()->cdd_close(h); }
extern "C" DWORD CDD_Read(DWORD h, LPVOID b, DWORD n)  { return CerfStubLoadedBody()->cdd_read(h, b, n); }
extern "C" DWORD CDD_Write(DWORD h, LPCVOID b, DWORD n){ return CerfStubLoadedBody()->cdd_write(h, b, n); }
extern "C" DWORD CDD_Seek(DWORD h, LONG a, WORD t)     { return CerfStubLoadedBody()->cdd_seek(h, a, t); }
extern "C" BOOL  CDD_IOControl(DWORD h, DWORD code, PBYTE pi, DWORD il,
                               PBYTE po, DWORD ol, PDWORD pa) {
    return CerfStubLoadedBody()->cdd_ioctl(h, code, pi, il, po, ol, pa);
}
extern "C" int InitializeFlipping(DWORD display) {
    return CerfStubLoadedBody()->init_flipping(display);
}
extern "C" int TerminateFlipping(DWORD display) {
    return CerfStubLoadedBody()->term_flipping(display);
}
extern "C" int ScreenUpdateByFlipEx(DWORD display, const DWORD* record) {
    return CerfStubLoadedBody()->screen_update(display, record);
}
extern "C" DWORD ClaimFreeBuffer(DWORD display) {
    return CerfStubLoadedBody()->claim_free_buffer(display);
}
extern "C" int SetSurfaceModified(void* surface) {
    return CerfStubLoadedBody()->set_surface_modified(surface);
}

extern "C" BOOL APIENTRY DllEntryPoint(HANDLE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) CerfStubSetInst((HMODULE)hInst);
    return TRUE;
}
