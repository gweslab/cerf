/* Physical-memory dump worker: sweep [base, base+length) in 1 MB windows,
   map each with VirtualCopy(...PAGE_PHYSICAL), read page-by-page under SEH,
   write linearly so file offset == physical offset. */

#include "romdump.h"

/* windows.h includes <excpt.h> only on _WIN32_WCE >= 101; the CE 1.0 build
   needs it directly for the __except filter values (EXCEPTION_EXECUTE_HANDLER). */
#include <excpt.h>

/* Copy one page from a mapped physical window. An unpopulated static bank
   data-aborts on touch; catch it, fill 0xFF, and report the fill so the
   linear file keeps offset == PA (no skipped bytes). Kept in its own
   function so the SEH frame stays minimal and never wraps the file I/O. */
static BOOL ReadPageGuarded(BYTE* dst, const BYTE* src) {
    __try {
        memcpy(dst, src, PAGE_BYTES);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        memset(dst, 0xFF, PAGE_BYTES);
        return FALSE;
    }
}

/* Bounded wide-string copy - CE has no lstrcpynW; keep it dependency-free. */
static void CopyStrW(LPWSTR dst, LPCWSTR src, int cch) {
    int i = 0;
    if (cch <= 0) return;
    while (i < cch - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

typedef struct {
    const BYTE* src;
    void*       va;
} PhysWindow;

static void OpenPhysWindow(PhysWindow* win, DWORD pa, VirtualCopyFn pVirtualCopy) {
    win->src = NULL;
    win->va  = NULL;
    if (pVirtualCopy) {
        win->va = VirtualAlloc(NULL, WIN_BYTES, MEM_RESERVE, PAGE_NOACCESS);
        if (win->va && pVirtualCopy(win->va, (LPVOID)(pa >> 8), WIN_BYTES,
                                    PAGE_READWRITE | PAGE_NOCACHE | PAGE_PHYSICAL))
            win->src = (const BYTE*)win->va;
        return;
    }
#if defined(MIPS)
    if (pa < 0x20000000u && pa + WIN_BYTES <= 0x20000000u)
        win->src = (const BYTE*)(0xA0000000u | pa);
#endif
}

static void ClosePhysWindow(PhysWindow* win) {
    if (win->va) VirtualFree(win->va, 0, MEM_RELEASE);
}

static DWORD ReadChunk(const PhysWindow* win, DWORD off, BYTE* buf) {
    DWORD p, faults = 0;
    for (p = 0; p < CHUNK_BYTES; p += PAGE_BYTES) {
        if (win->src && ReadPageGuarded(buf + p, win->src + off + p)) continue;
        memset(buf + p, 0xFF, PAGE_BYTES);
        faults++;
    }
    return faults;
}

/* Post one heap-copied log line to the UI thread; StepDumpOnMessage frees it. */
static void PostLine(HWND hwnd, LPCWSTR s) {
    int    cch = lstrlenW(s) + 1;
    WCHAR* p   = (WCHAR*)LocalAlloc(LPTR, (DWORD)cch * sizeof(WCHAR));
    if (!p) return;
    memcpy(p, s, (DWORD)cch * sizeof(WCHAR));
    PostMessageW(hwnd, WM_APP_LOG, 0, (LPARAM)p);
}

DWORD WINAPI DumpThread(LPVOID param) {
    AppState* st = (AppState*)param;
    BYTE*  buf;
    DWORD  seg_bytes, num_segs, s;
    int    failed = 0, stopped = 0, last_pct = -1;
    VirtualCopyFn pVirtualCopy;

    buf = (BYTE*)LocalAlloc(LPTR, CHUNK_BYTES);
    if (!buf) {
        CopyStrW(st->err, L"Out of memory allocating read buffer.", 160);
        st->ok = 0; st->finished = 1;
        PostMessageW(st->hwnd, WM_APP_DONE, 0, 0);
        return 0;
    }

    pVirtualCopy = (VirtualCopyFn)CoreProc(L"VirtualCopy");

    /* length and seg_bytes are whole megabytes; the last part is the remainder
       (this_len < seg_bytes), never padded up - it can be smaller, never bigger. */
    seg_bytes = st->segmented ? st->seg_bytes : st->length;
    if (seg_bytes == 0) seg_bytes = st->length;
    num_segs = (st->length + seg_bytes - 1) / seg_bytes;
    if (num_segs == 0) num_segs = 1;
    st->seg_total = num_segs;

    for (s = 0; s < num_segs; s++) {
        WCHAR  path[MAX_PATH + 8], line[MAX_PATH + 96];
        HANDLE hf;
        DWORD  seg_off   = s * seg_bytes;
        DWORD  this_len  = st->length - seg_off;
        DWORD  seg_start, w;

        if (st->cancel) break;
        if (this_len > seg_bytes) this_len = seg_bytes;
        seg_start = st->base + seg_off;

        if (st->segmented)
            wsprintfW(path, L"%s.%03u", st->outpath, (unsigned)(s + 1));
        else
            CopyStrW(path, st->outpath, MAX_PATH + 8);

        wsprintfW(line, L"Start  0x%08X   part %u/%u",
                  seg_start, (unsigned)(s + 1), (unsigned)num_segs);
        PostLine(st->hwnd, line);

        hf = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            wsprintfW(st->err, L"Cannot create %s (read-only or full?).", path);
            wsprintfW(line, L"Failed 0x%08X   cannot create file", seg_start);
            PostLine(st->hwnd, line);
            failed = 1; break;
        }

        for (w = 0; w < this_len; w += WIN_BYTES) {
            DWORD pa = seg_start + w;
            DWORD c, wr, pct;
            PhysWindow win;
            if (st->cancel) break;
            st->cur_pa = pa;
            OpenPhysWindow(&win, pa, pVirtualCopy);
            for (c = 0; c < WIN_BYTES && !stopped; c += CHUNK_BYTES) {
                st->fault_pages += ReadChunk(&win, c, buf);
                for (;;) {
                    wr = 0;
                    if (WriteFile(hf, buf, CHUNK_BYTES, &wr, NULL) && wr == CHUNK_BYTES) break;
                    st->fail_pa = pa;
                    st->storage_retry = 0;
                    PostMessageW(st->hwnd, WM_APP_STORAGE, 0, 0);
                    WaitForSingleObject(st->seg_event, INFINITE);
                    if (st->cancel || !st->storage_retry) {
                        wsprintfW(line, L"Stopped 0x%08X   storage full", pa);
                        PostLine(st->hwnd, line);
                        stopped = 1; break;
                    }
                    SetFilePointer(hf, (LONG)(w + c), NULL, FILE_BEGIN);
                }
            }
            ClosePhysWindow(&win);
            if (stopped || st->cancel) break;
            st->bytes_done = seg_off + w + WIN_BYTES;
            pct = st->length ? (st->bytes_done * 100) / st->length : 0;
            if ((int)pct != last_pct) {
                last_pct = (int)pct;
                wsprintfW(line, L"  0x%08X   %u/%u MB   %u%%",
                          st->base + st->bytes_done,
                          (unsigned)(st->bytes_done >> 20),
                          (unsigned)(st->length >> 20), (unsigned)pct);
                PostLine(st->hwnd, line);
            }
        }

        FlushFileBuffers(hf);
        CloseHandle(hf);
        if (failed || st->cancel || stopped) break;

        st->seg_start_pa = seg_start;
        st->seg_end_pa   = seg_start + this_len - 1;
        st->segs_written++;
        wsprintfW(line, L"Done   0x%08X-0x%08X   part %u/%u   0xFF pages %u",
                  st->seg_start_pa, st->seg_end_pa,
                  (unsigned)(s + 1), (unsigned)num_segs,
                  (unsigned)st->fault_pages);
        PostLine(st->hwnd, line);

        /* Pause after every part except the last: the UI prompts and the worker
           blocks here until the answer (Stop or No signals the event too). */
        if (st->segmented && s + 1 < num_segs) {
            st->seg_index = s + 1;
            st->seg_continue = 0;
            PostMessageW(st->hwnd, WM_APP_SEGMENT, 0, 0);
            WaitForSingleObject(st->seg_event, INFINITE);
            if (!st->seg_continue) { stopped = 1; break; }
        }
    }

    LocalFree(buf);
    st->ok = (!failed && !st->cancel && !stopped);
    st->finished = 1;
    PostMessageW(st->hwnd, WM_APP_DONE, 0, 0);
    return 0;
}
