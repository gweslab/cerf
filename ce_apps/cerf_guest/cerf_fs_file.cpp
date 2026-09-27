#include "cerf_fs_driver.h"

#include <windows.h>

static void SetName(CerfFsServerPB* pb, PCWSTR name) {
    int n = lstrlenW(name);
    if (n > (int)CERF_FS_MAX_LFN) n = (int)CERF_FS_MAX_LFN;
    memcpy(pb->u.fName, name, n * sizeof(WCHAR));
    pb->u.fName[n] = 0;
    pb->u.fNameLength = (unsigned short)(n * sizeof(WCHAR));
}

static unsigned short OpenModeFrom(DWORD access, DWORD share) {
    unsigned short m;
    if ((access & (GENERIC_READ | GENERIC_WRITE)) == (GENERIC_READ | GENERIC_WRITE))
        m = CERF_FS_ACCESS_RW;
    else if (access & GENERIC_WRITE)
        m = CERF_FS_ACCESS_WRITE;
    else
        m = CERF_FS_ACCESS_READ;
    if ((share & (FILE_SHARE_READ | FILE_SHARE_WRITE)) == (FILE_SHARE_READ | FILE_SHARE_WRITE))
        m |= CERF_FS_SHARE_DENY_NONE;
    else if (share & FILE_SHARE_READ)
        m |= CERF_FS_SHARE_DENY_WRITE;
    else if (share & FILE_SHARE_WRITE)
        m |= CERF_FS_SHARE_DENY_READ;
    else
        m |= CERF_FS_SHARE_DENY_RW;
    return m;
}

void CerfFsDosToFiletime(unsigned long dosdt, FILETIME* out) {
    WORD dd = HIWORD(dosdt);
    WORD dt = LOWORD(dosdt);
    SYSTEMTIME st;
    FILETIME local;
    out->dwLowDateTime = 0;
    out->dwHighDateTime = 0;
    memset(&st, 0, sizeof(st));
    st.wYear   = (WORD)(1980 + ((dd >> 9) & 0x7F));
    st.wMonth  = (dd >> 5) & 0x0F;
    st.wDay    = dd & 0x1F;
    st.wHour   = (dt >> 11) & 0x1F;
    st.wMinute = (dt >> 5) & 0x3F;
    st.wSecond = (dt & 0x1F) * 2;
    if (st.wMonth == 0 || st.wDay == 0) return;
    if (SystemTimeToFileTime(&st, &local))
        LocalFileTimeToFileTime(&local, out);
}
static unsigned long FiletimeToDos(const FILETIME* ft) {
    FILETIME local;
    SYSTEMTIME st;
    WORD dd, dt;
    if (!FileTimeToLocalFileTime(ft, &local)) return 0;
    if (!FileTimeToSystemTime(&local, &st) || st.wYear < 1980) return 0;
    dd = (WORD)(((st.wYear - 1980) << 9) | (st.wMonth << 5) | st.wDay);
    dt = (WORD)((st.wHour << 11) | (st.wMinute << 5) | (st.wSecond / 2));
    return MAKELONG(dt, dd);
}

static unsigned long DoOpen(PCWSTR name, unsigned short mode, unsigned short* slot) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned long e;
    SetName(pb, name);
    pb->fOpenMode = mode;
    e = CerfFsCall(pb, CERF_FS_OP_OPEN);
    if (e == CERF_FS_OK) *slot = pb->fHandle;
    return e;
}
static unsigned long DoCreate(PCWSTR name) {
    CerfFsServerPB* pb = CerfFsPb();
    SetName(pb, name);
    return CerfFsCall(pb, CERF_FS_OP_CREATE);
}

HANDLE CerfFsCreateFileW(CerfVol* vol, HANDLE hProc, PCWSTR name, DWORD access,
                         DWORD share, PSECURITY_ATTRIBUTES sa, DWORD create,
                         DWORD flags, HANDLE templ) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned short mode = OpenModeFrom(access, share);
    unsigned short slot = 0;
    unsigned long e;
    HANDLE h = INVALID_HANDLE_VALUE;
    CerfFile* fc;
    int already = 0;
    (void)vol; (void)sa; (void)flags; (void)templ;

    CerfFsLock();
    switch (create) {
        case CREATE_NEW:
            e = DoCreate(name);
            if (e == CERF_FS_OK) e = DoOpen(name, mode, &slot);
            break;
        case CREATE_ALWAYS:
            /* learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
               CREATE_ALWAYS: "If the specified file exists and is writable, the
               function truncates the file, the function succeeds, and last-error
               code is set to ERROR_ALREADY_EXISTS". */
            e = DoOpen(name,
                       (unsigned short)((mode & CERF_FS_SHARE_MASK) | CERF_FS_ACCESS_WRITE),
                       &slot);
            if (e == CERF_FS_OK) {
                pb->fHandle = slot; pb->fPosition = 0;
                e = CerfFsCall(pb, CERF_FS_OP_SET_EOF);
                pb->fHandle = slot;
                CerfFsCall(pb, CERF_FS_OP_CLOSE);
                if (e == CERF_FS_OK) {
                    e = DoOpen(name, mode, &slot);
                    if (e == CERF_FS_OK) already = 1;
                }
            } else if (e == CERF_FS_E_FILE_NOT_FOUND) {
                e = DoCreate(name);
                if (e == CERF_FS_OK) e = DoOpen(name, mode, &slot);
            }
            break;
        case OPEN_ALWAYS:
            e = DoOpen(name, mode, &slot);
            if (e == CERF_FS_OK) {
                already = 1;
            } else if (e == CERF_FS_E_FILE_NOT_FOUND) {
                e = DoCreate(name);
                if (e == CERF_FS_OK) e = DoOpen(name, mode, &slot);
            }
            break;
        case TRUNCATE_EXISTING:
            e = DoOpen(name, mode, &slot);
            if (e == CERF_FS_OK) {
                pb->fHandle = slot; pb->fPosition = 0;
                e = CerfFsCall(pb, CERF_FS_OP_SET_EOF);
                if (e != CERF_FS_OK) {
                    pb->fHandle = slot;
                    CerfFsCall(pb, CERF_FS_OP_CLOSE);
                }
            }
            break;
        case OPEN_EXISTING:
            e = DoOpen(name, mode, &slot);
            break;
        default:
            /* learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
               dwCreationDisposition: "This parameter must be one of the following
               values, which cannot be combined". */
            e = ERROR_INVALID_PARAMETER;
            break;
    }

    if (e == CERF_FS_OK) {
        fc = (CerfFile*)LocalAlloc(LPTR, sizeof(CerfFile));
        if (fc) {
            fc->fHandle = slot;
            fc->pos = 0;
            h = CerfFsMakeHandle(CerfFsFileApi(), fc, hProc);
            if (h == INVALID_HANDLE_VALUE) {
                pb->fHandle = slot;
                CerfFsCall(pb, CERF_FS_OP_CLOSE);
                LocalFree(fc);
                e = ERROR_OUTOFMEMORY;
            }
        } else {
            pb->fHandle = slot;
            CerfFsCall(pb, CERF_FS_OP_CLOSE);
            e = ERROR_OUTOFMEMORY;
        }
    }
    CerfFsUnlock();
    if (h == INVALID_HANDLE_VALUE) {
        CerfFsResultToBool(e);
    } else if (create == CREATE_ALWAYS || create == OPEN_ALWAYS) {
        SetLastError(already ? ERROR_ALREADY_EXISTS : 0);
    }
    return h;
}

static BOOL RwAtSeek(CerfFile* fc, PVOID buf, DWORD count, PDWORD done,
                     unsigned long op, unsigned long pos) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned char* io = CerfFsIoBuf();
    DWORD total = 0;
    unsigned long e = CERF_FS_OK;

    while (total < count) {
        DWORD chunk = count - total;
        if (chunk > CERF_FS_MAX_IO) chunk = CERF_FS_MAX_IO;
        pb->fHandle = fc->fHandle;
        pb->fPosition = pos + total;
        pb->fSize = chunk;
        if (op == CERF_FS_OP_WRITE)
            memcpy(io, (unsigned char*)buf + total, chunk);
        e = CerfFsCall(pb, op);
        if (e != CERF_FS_OK) break;
        if (op == CERF_FS_OP_READ) memcpy((unsigned char*)buf + total, io, pb->fSize);
        total += pb->fSize;
        if (pb->fSize < chunk) break;
    }
    if (done) *done = total;
    if (e != CERF_FS_OK && total == 0) return CerfFsResultToBool(e);
    return TRUE;
}

BOOL CerfFsReadFileWithSeek(CerfFile* f, PVOID buf, DWORD count, PDWORD done,
                            OVERLAPPED* ov, DWORD low, DWORD high) {
    BOOL ok;
    (void)high;
    /* sharp_mobilon_hc4100_hpc2 fatfs.dll 0x1FB57A4 -> 0x1FB564C: read at the handle
       position and advance it; jornada820 fatfs.dll 0x1F83EB0 -> 0x1F83C40: read at *offset. */
    if (!CerfFsSeekTakesOffset()) return CerfFsReadFile(f, buf, count, done, ov);
    CerfFsLock();
    ok = RwAtSeek(f, buf, count, done, CERF_FS_OP_READ, low);
    CerfFsUnlock();
    return ok;
}
BOOL CerfFsWriteFileWithSeek(CerfFile* f, const void* buf, DWORD count, PDWORD done,
                             OVERLAPPED* ov, DWORD low, DWORD high) {
    BOOL ok;
    (void)ov; (void)high;
    CerfFsLock();
    ok = RwAtSeek(f, (PVOID)buf, count, done, CERF_FS_OP_WRITE, low);
    CerfFsUnlock();
    return ok;
}
BOOL CerfFsReadFile(CerfFile* f, PVOID buf, DWORD count, PDWORD done, OVERLAPPED* ov) {
    BOOL ok;
    CerfFsLock();
    ok = RwAtSeek(f, buf, count, done, CERF_FS_OP_READ, f->pos);
    if (ok && done) f->pos += *done;
    CerfFsUnlock();
    (void)ov;
    return ok;
}
BOOL CerfFsWriteFile(CerfFile* f, const void* buf, DWORD count, PDWORD done, OVERLAPPED* ov) {
    BOOL ok;
    CerfFsLock();
    ok = RwAtSeek(f, (PVOID)buf, count, done, CERF_FS_OP_WRITE, f->pos);
    if (ok && done) f->pos += *done;
    CerfFsUnlock();
    (void)ov;
    return ok;
}

static unsigned long FcbSize(CerfFile* fc) {
    CerfFsServerPB* pb = CerfFsPb();
    pb->fHandle = fc->fHandle;
    if (CerfFsCall(pb, CERF_FS_OP_GET_FCB_INFO) == CERF_FS_OK) return pb->fSize;
    return 0;
}

DWORD CerfFsSetFilePointer(CerfFile* f, LONG dist, PLONG distHigh, DWORD method) {
    unsigned long base;
    (void)distHigh;
    CerfFsLock();
    base = (method == FILE_CURRENT) ? f->pos
         : (method == FILE_END)     ? FcbSize(f)
         :                            0;
    f->pos = base + (unsigned long)dist;
    CerfFsUnlock();
    return f->pos;
}

DWORD CerfFsGetFileSize(CerfFile* f, PDWORD sizeHigh) {
    DWORD sz;
    CerfFsLock();
    sz = FcbSize(f);
    CerfFsUnlock();
    if (sizeHigh) *sizeHigh = 0;
    return sz;
}

BOOL CerfFsGetFileInformationByHandle(CerfFile* f, PBY_HANDLE_FILE_INFORMATION fi) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned long e;
    CerfFsLock();
    pb->fHandle = f->fHandle;
    e = CerfFsCall(pb, CERF_FS_OP_GET_FCB_INFO);
    if (e == CERF_FS_OK) {
        memset(fi, 0, sizeof(*fi));
        fi->dwFileAttributes = pb->fFileAttributes;
        fi->nFileSizeLow = pb->fSize;
        CerfFsDosToFiletime(pb->fFileCreateTimeDate, &fi->ftCreationTime);
        CerfFsDosToFiletime(pb->fFileTimeDate, &fi->ftLastWriteTime);
        fi->ftLastAccessTime = fi->ftLastWriteTime;
        fi->nNumberOfLinks = 1;
        /* devemu_wm5 nk.exe 0x8009A12C OpenExe: oe.bIsOID =
           GetFileInformationByHandle(hf, &bhfi) && bhfi.dwOID != 0xFFFFFFFF. */
        fi->dwOID = (DWORD)-1;
    }
    CerfFsUnlock();
    return CerfFsResultToBool(e);
}

BOOL CerfFsGetFileTime(CerfFile* f, FILETIME* create, FILETIME* access, FILETIME* write) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned long e;
    CerfFsLock();
    pb->fHandle = f->fHandle;
    e = CerfFsCall(pb, CERF_FS_OP_GET_FCB_INFO);
    if (e == CERF_FS_OK) {
        if (create) CerfFsDosToFiletime(pb->fFileCreateTimeDate, create);
        if (write)  CerfFsDosToFiletime(pb->fFileTimeDate, write);
        if (access) CerfFsDosToFiletime(pb->fFileTimeDate, access);
    }
    CerfFsUnlock();
    return CerfFsResultToBool(e);
}

BOOL CerfFsSetFileTime(CerfFile* f, const FILETIME* create, const FILETIME* access,
                       const FILETIME* write) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned long e;
    WCHAR name[CERF_FS_MAX_LFN + 1];
    unsigned short attrs;
    (void)create; (void)access;
    CerfFsLock();
    pb->fHandle = f->fHandle;
    e = CerfFsCall(pb, CERF_FS_OP_GET_FCB_INFO);
    if (e == CERF_FS_OK) {
        int n = pb->u.fNameLength / sizeof(WCHAR);
        if (n > (int)CERF_FS_MAX_LFN) n = (int)CERF_FS_MAX_LFN;
        memcpy(name, pb->u.fName, n * sizeof(WCHAR));
        name[n] = 0;
        attrs = pb->fFileAttributes;
        SetName(pb, name);
        pb->fFileAttributes = attrs;
        pb->fFileTimeDate = write ? FiletimeToDos(write) : 0;
        e = CerfFsCall(pb, CERF_FS_OP_SET_ATTRS);
    }
    CerfFsUnlock();
    return CerfFsResultToBool(e);
}

BOOL CerfFsSetEndOfFile(CerfFile* f) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned long e;
    CerfFsLock();
    pb->fHandle = f->fHandle;
    pb->fPosition = f->pos;
    e = CerfFsCall(pb, CERF_FS_OP_SET_EOF);
    CerfFsUnlock();
    return CerfFsResultToBool(e);
}

BOOL CerfFsFlushFileBuffers(CerfFile* f) {
    (void)f;
    return TRUE;
}

BOOL CerfFsFileIoControl(CerfFile* f, DWORD code, PVOID pIn, DWORD inLen,
                         PVOID pOut, DWORD outLen, PDWORD pActualOut,
                         OVERLAPPED* ov) {
    (void)f; (void)pIn; (void)inLen; (void)pOut; (void)outLen; (void)ov;
    if (pActualOut) *pActualOut = 0;
    CERF_LOG_X("cerf_guest: foldershare file IOCTL unsupported code", code);
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

BOOL CerfFsCloseFile(CerfFile* f) {
    CerfFsServerPB* pb = CerfFsPb();
    unsigned long e;
    CerfFsLock();
    pb->fHandle = f->fHandle;
    e = CerfFsCall(pb, CERF_FS_OP_CLOSE);
    CerfFsUnlock();
    LocalFree(f);
    return CerfFsResultToBool(e);
}
